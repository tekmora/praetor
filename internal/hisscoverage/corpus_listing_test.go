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
	"sync/atomic"
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

// TestBucketListingChecksCancellationAtEOF preserves cancellation and the terminal
// read result, including a filesystem error, through the bucket reader used by Verify.
func TestBucketListingChecksCancellationAtEOF(t *testing.T) {
	dir := listingCursor(t, t.TempDir())
	for _, readErr := range [...]error{io.EOF, os.ErrPermission} {
		ctx, cancel := context.WithCancel(t.Context())
		next := func(string, int) ([]os.DirEntry, error) {
			cancel()
			return nil, readErr
		}
		ctx = context.WithValue(ctx, bucketReaderKey{}, next)
		entries, err := readBucketEntries(ctx, dir)
		cancel()
		if entries != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, readErr) {
			t.Fatalf("final directory read: entries=%v err=%v, want cancellation and %v", entries, err, readErr)
		}
	}
}

// TestCompoundEOFDiscardsPartialListing exercises both the collector and Verify's bucket
// boundary. A live context cannot turn a terminal permission failure into a partial success.
func TestCompoundEOFDiscardsPartialListing(t *testing.T) {
	dir := listingCursor(t, t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), contextopt.MaxDuration)
	defer cancel()
	next := func(int) ([]os.DirEntry, error) {
		return []os.DirEntry{namedTestDirectory{name: "partial"}}, errors.Join(io.EOF, os.ErrPermission)
	}
	t.Run("collector", func(t *testing.T) {
		entries, err := collectBucketEntries(ctx, next)
		requireCompoundEOF(t, entries, err)
	})
	t.Run("corpus", func(t *testing.T) {
		stub := func(_ string, n int) ([]os.DirEntry, error) { return next(n) }
		entries, err := readBucketEntries(context.WithValue(ctx, bucketReaderKey{}, stub), dir)
		requireCompoundEOF(t, entries, err)
		if !strings.Contains(err.Error(), dir.Name()) {
			t.Fatalf("bucket missing from listing error: %v", err)
		}
	})
}

// TestFinalDirectorySlotRequiresBareEOF checks completion when the last chunk fills
// the allowance. A wrapper around EOF still carries a diagnostic that must survive.
func TestFinalDirectorySlotRequiresBareEOF(t *testing.T) {
	readErr := io.EOF
	next := func(int) ([]int, error) { return []int{42}, readErr }
	entries, err := contextopt.CollectDirectoryEntries(t.Context(), 1, next)
	if err != nil || len(entries) != 1 || entries[0] != 42 {
		t.Fatalf("bare EOF at final slot: entries=%v err=%v", entries, err)
	}
	readErr = fmt.Errorf("directory cursor: %w", io.EOF)
	entries, err = contextopt.CollectDirectoryEntries(t.Context(), 1, next)
	if entries != nil || !errors.Is(err, readErr) {
		t.Fatalf("wrapped EOF at final slot: entries=%v err=%v", entries, err)
	}
}

// requireCompoundEOF requires both causes and discards every entry from the failed read.
func requireCompoundEOF(t *testing.T, entries []os.DirEntry, err error) {
	t.Helper()
	if entries != nil || !errors.Is(err, io.EOF) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("partial listing: entries=%v err=%v, want EOF and permission denied", entries, err)
	}
}

// cancelAfterRead cancels the real context on the first status check after the cursor read.
type cancelAfterRead struct {
	context.Context
	cancel  context.CancelFunc
	checked atomic.Bool
}

// Err admits the initial read and delivers cancellation at its completion boundary.
func (c *cancelAfterRead) Err() error {
	if c.checked.Swap(true) {
		c.cancel()
	}
	return c.Context.Err()
}

// TestNativeListingPreservesTerminalEOF reads an empty directory with the platform's
// native reader. Returning only cancellation from that reader loses the observed EOF.
func TestNativeListingPreservesTerminalEOF(t *testing.T) {
	dir := listingCursor(t, t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), contextopt.MaxDuration)
	defer cancel()
	entries, err := dir.ReadEntries(&cancelAfterRead{Context: ctx, cancel: cancel}, 1)
	if entries != nil || !errors.Is(err, io.EOF) || !errors.Is(err, context.Canceled) {
		t.Fatalf("native terminal read: entries=%v err=%v, want EOF and cancellation", entries, err)
	}
}

// listingCursor opens an independent pinned cursor in the test bucket.
func listingCursor(t *testing.T, path string) *contextopt.SnapshotDirectory {
	t.Helper()
	cursor, err := contextopt.OpenSnapshotDirectoryIn(t.Context(), path, ".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cursor.Close(); err != nil {
			t.Error(err)
		}
	})
	return cursor
}

// failedLookup wraps a regular entry with the supplied metadata lookup failure.
type failedLookup struct {
	os.DirEntry
	cause error
}

// Info associates the lookup failure with the entry that produced it.
func (e failedLookup) Info() (os.FileInfo, error) {
	return nil, &os.PathError{Op: "stat", Path: e.Name(), Err: e.cause}
}

// TestVerifyNamesFailedLookups requires a finding for every listed lookup failure.
func TestVerifyNamesFailedLookups(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, "a.go", cleanGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "b.go", cleanGo)
	ctx := withBucketReader(t.Context(), func(_ string, entries []os.DirEntry) []os.DirEntry {
		for i, entry := range entries {
			entries[i] = failedLookup{entry, os.ErrPermission}
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

// TestVerifyMissingLookupPreservesClose checks the complete diagnostic through Verify.
func TestVerifyMissingLookupPreservesClose(t *testing.T) {
	const name = "missing.go"
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, name, cleanGo)
	closeErr := errors.New("close metadata handle failed")
	ctx := withBucketReader(t.Context(), func(_ string, entries []os.DirEntry) []os.DirEntry {
		for i, entry := range entries {
			entries[i] = failedLookup{entry, errors.Join(os.ErrNotExist, closeErr)}
		}
		return entries
	})
	report := verifySnapshot(t, ctx, root)
	requireSnapshotFinding(t, report, 0, name, closeErr.Error())
	if !strings.Contains(report.Findings[0].Detail, os.ErrNotExist.Error()) {
		t.Fatalf("missing lookup cause: %+v", report.Findings)
	}
}

// failedCapture returns the read and close result that captureFile must report.
type failedCapture struct{ err error }

// ReadListedSnapshot returns the fixture handle's terminal diagnostic.
func (r failedCapture) ReadListedSnapshot(context.Context, string, os.FileInfo) ([]byte, error) {
	return nil, r.err
}

// TestCaptureFailurePreservesClose distinguishes a single wrapped change from
// the same change joined to a close failure at the fixture reader boundary.
func TestCaptureFailurePreservesClose(t *testing.T) {
	const name = "child.go"
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, name, cleanGo)
	listed, err := os.Stat(filepath.Join(bucketPath(root, "HISS-01", "go", bucketNegative), name))
	if err != nil {
		t.Fatal(err)
	}
	bucket := bucketSnapshot{stage: fixtureStage{ruleID: "HISS-01", language: "go"}}
	closeErr := errors.New("close fixture handle failed")
	for _, cause := range [...]error{os.ErrNotExist, contextopt.ErrSourceNotRegular} {
		for _, cleanup := range [...]error{nil, closeErr} {
			var report Report
			err := errors.Join(fmt.Errorf("read fixture: %w", cause), cleanup)
			if err := bucket.captureFile(t.Context(), failedCapture{err}, bucketNegative, listed, &report); err != nil {
				t.Fatal(err)
			}
			if cleanup == nil {
				requireSnapshotFinding(t, &report, 0, name, "changed during verification")
				continue
			}
			requireSnapshotFinding(t, &report, 0, name, "incomplete replay")
			detail := report.Findings[0].Detail
			if !strings.Contains(detail, cause.Error()) || !strings.Contains(detail, closeErr.Error()) {
				t.Fatalf("lost a capture or close diagnostic: %q", detail)
			}
		}
	}
}

// TestVerifyUnionBucketIsIncomplete requires the native refusal to name the bucket
// in the report even when a reader also returns entries from that directory.
func TestVerifyUnionBucketIsIncomplete(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, "ignored.go", cleanGo)
	stub := func(_ string, _ int) ([]os.DirEntry, error) {
		return []os.DirEntry{namedTestDirectory{name: "partial"}}, contextopt.ErrUnionDirectory
	}
	report := verifySnapshot(t, context.WithValue(t.Context(), bucketReaderKey{}, stub), root)
	requireSnapshotFinding(t, report, 0, "", "incomplete replay")
	finding := report.Findings[0]
	if finding.Bucket != bucketNegative || !strings.Contains(finding.Detail, "MNT_UNION") ||
		!strings.Contains(finding.Detail, bucketNegative) || report.Passed() {
		t.Fatalf("union-mounted bucket: %+v", report)
	}
}
