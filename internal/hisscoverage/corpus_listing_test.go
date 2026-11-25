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
