// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

// TestVerifyShortBucketReadsPreserveOverflow supplies 4096 entries followed by the sentinel
// through the same cursor. Each call must request only the remaining entry allowance.
func TestVerifyShortBucketReadsPreserveOverflow(t *testing.T) {
	root := t.TempDir()
	bucket := bucketPath(root, "HISS-01", "go", bucketNegative)
	if err := contextopt.EnsureDirectory(t.Context(), bucket, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(bucket)
	if err != nil {
		t.Fatal(err)
	}
	dir := fs.FileInfoToDirEntry(info)
	reads := 0
	next := func(path string, n int) ([]os.DirEntry, error) {
		if filepath.Base(path) != bucketNegative {
			t.Fatalf("unexpected listing of %q", path)
		}
		reads++
		return shortDirectoryChunk(t, dir, reads, n)
	}
	ctx := context.WithValue(t.Context(), bucketReaderKey{}, next)
	requireDirectoryOverflow(t, ctx, root, "z-overflow")
	if reads != 2 {
		t.Fatalf("reads = %d, want 2", reads)
	}
}

// namedTestDirectory gives each synthetic directory entry its own flat name.
type namedTestDirectory struct {
	os.DirEntry
	name string
}

// Name returns the unique directory name supplied by the stub.
func (e namedTestDirectory) Name() string { return e.name }

// shortDirectoryChunk serves a short first batch and a one-entry overflow batch.
func shortDirectoryChunk(t *testing.T, dir os.DirEntry, read, n int) ([]os.DirEntry, error) {
	t.Helper()
	switch {
	case read == 1 && n == 4097:
		chunk := make([]os.DirEntry, 4096)
		for i := range chunk {
			chunk[i] = namedTestDirectory{dir, fmt.Sprintf("dir-%04d", i)}
		}
		return chunk, nil
	case read == 2 && n == 1:
		return []os.DirEntry{namedTestDirectory{dir, "z-overflow"}}, nil
	default:
		t.Fatalf("unexpected read %d requesting %d entries", read, n)
		return nil, io.EOF
	}
}

// TestBucketListingRejectsStalledCursor refuses to certify an empty successful read as EOF.
func TestBucketListingRejectsStalledCursor(t *testing.T) {
	reads := 0
	next := func(int) ([]os.DirEntry, error) {
		reads++
		return nil, nil
	}
	entries, err := collectBucketEntries(t.Context(), next)
	if !errors.Is(err, io.ErrNoProgress) || entries != nil || reads != 1 {
		t.Fatalf("stalled cursor: %v, entries %v, reads %d", err, entries, reads)
	}
}

// TestBucketListingChecksCancellationBetweenReads cancels a partially consumed cursor.
func TestBucketListingChecksCancellationBetweenReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reads := 0
	next := func(int) ([]os.DirEntry, error) {
		reads++
		cancel()
		return []os.DirEntry{nil}, nil
	}
	entries, err := collectBucketEntries(ctx, next)
	if !errors.Is(err, context.Canceled) || entries != nil || reads != 1 {
		t.Fatalf("canceled cursor: %v, entries %v, reads %d", err, entries, reads)
	}
}

// TestBucketListingChecksCancellationAtEOF refuses a terminal chunk when cancellation
// occurs inside the last directory read. There is no next iteration to catch it.
func TestBucketListingChecksCancellationAtEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	next := func(int) ([]os.DirEntry, error) {
		cancel()
		return nil, io.EOF
	}
	entries, err := collectBucketEntries(ctx, next)
	if entries != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("final directory read completed after cancellation: %v, %v", entries, err)
	}
}

// failedLookup wraps a regular entry with a metadata lookup error other than ENOENT.
type failedLookup struct{ os.DirEntry }

// Info returns a named permission failure as a filesystem lookup would.
func (e failedLookup) Info() (os.FileInfo, error) {
	return nil, &os.PathError{Op: "stat", Path: e.Name(), Err: os.ErrPermission}
}

// TestVerifyNamesFailedLookups requires a finding for every listed lookup failure.
func TestVerifyNamesFailedLookups(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, "a.go", cleanGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "b.go", cleanGo)
	ctx := withBucketReader(t.Context(), func(_ string, entries []os.DirEntry) []os.DirEntry {
		for i, entry := range entries {
			entries[i] = failedLookup{entry}
		}
		return entries
	})
	report := verifySnapshot(t, ctx, root)
	if report.Fixtures != 0 || len(report.Findings) != 2 {
		t.Fatalf("expected two failed lookups, got %+v", report)
	}
	for i, name := range [...]string{"a.go", "b.go"} {
		finding := report.Findings[i]
		if finding.Fixture != name || !strings.Contains(finding.Detail, "incomplete replay") {
			t.Fatalf("expected a named lookup failure on %q, got %+v", name, finding)
		}
	}
}
