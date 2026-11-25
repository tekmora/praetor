// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotSpillBoundary preserves exactly one MiB in memory and reads the excess
// byte from private storage. A truncated spill must fail and cleanup must remove it.
func TestSnapshotSpillBoundary(t *testing.T) {
	var store fixtureStore
	ctx := t.Context()
	full := bytes.Repeat([]byte{'a'}, 1<<20)
	first, err := store.save(ctx, "first", full)
	if err != nil || len(first.data) != len(full) || store.spill != nil {
		t.Fatalf("exact bound: retained %d bytes, spill %v, err %v", len(first.data), store.spill, err)
	}
	last, err := store.save(ctx, "last", []byte("x"))
	if err != nil || store.spill == nil {
		t.Fatalf("overflow did not spill: %v", err)
	}
	checkSpillRemoved(t, &store)
	checkSpilledByte(t, &store, last)
}

// checkSpilledByte reads the excess byte, then requires a truncated spill to fail.
func checkSpilledByte(t *testing.T, store *fixtureStore, last capturedFixture) {
	t.Helper()
	ctx := t.Context()
	if got, err := store.load(ctx, last); err != nil || string(got) != "x" || cap(last.data) != 0 {
		t.Fatalf("excess byte: got %q, resident capacity %d, err %v", got, cap(last.data), err)
	}
	if err := store.spill.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if data, err := store.load(ctx, last); err == nil || data != nil {
		t.Fatalf("truncated spill yielded %d bytes: %v", len(data), err)
	}
}

// checkSpillRemoved releases the private spill and verifies its path no longer exists.
func checkSpillRemoved(t *testing.T, store *fixtureStore) {
	t.Helper()
	path := store.spill.Name()
	t.Cleanup(func() {
		if err := store.close(); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("spill %q after cleanup: %v", path, err)
		}
	})
}

// TestVerifyRemovesSpill witnesses a live spill owned by Verify and checks its exact
// path after the verifier returns through each exit.
func TestVerifyRemovesSpill(t *testing.T) {
	for _, outcome := range [...]string{"success", "cancellation", "capture error"} {
		t.Run(outcome, func(t *testing.T) { verifySpillCleanup(t, outcome) })
	}
}

// verifySpillCleanup fills the resident budget in negative/ and spills the next file.
// A malformed gap fixture fails later, while capture is still in progress.
func verifySpillCleanup(t *testing.T, outcome string) {
	t.Helper()
	padding := strings.Repeat(strings.Repeat(" ", 1023)+"\n", 1024)
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, "a.go", cleanGo+padding[len(cleanGo):])
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "b.go", cleanGo)
	temp := t.TempDir()
	for _, key := range [...]string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, temp)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var spill string
	if outcome == "capture error" {
		writeCorpusFixture(t, root, "HISS-01", "go", bucketGap, "bad.go", "\x00")
		ctx = withBucketReader(ctx, func(dir string, entries []os.DirEntry) []os.DirEntry {
			if filepath.Base(dir) == bucketGap {
				spill = liveSpillPath(t, temp)
			}
			return entries
		})
	} else {
		ctx = afterFixtureCapture(ctx, func() {
			spill = liveSpillPath(t, temp)
			if outcome == "cancellation" {
				cancel()
			}
		})
	}
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	checkVerifySpillOutcome(t, outcome, report, err)
	if spill == "" {
		t.Fatal("Verify returned before the test witnessed its spill")
	}
	if _, err := os.Stat(spill); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Verify left %q: stat error %v", spill, err)
	}
}

// liveSpillPath identifies the single spill under the isolated temporary directory.
func liveSpillPath(t *testing.T, temp string) string {
	t.Helper()
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "hiss-corpus-") {
		t.Fatalf("expected one live spill under %q: %v, %v", temp, entries, err)
	}
	return filepath.Join(temp, entries[0].Name())
}

// checkVerifySpillOutcome requires the intended exit path in addition to cleanup.
func checkVerifySpillOutcome(t *testing.T, outcome string, report *Report, err error) {
	t.Helper()
	if outcome == "success" {
		if err != nil || !report.Passed() || report.Fixtures != 2 {
			t.Fatalf("verify with spill: %+v, %v", report, err)
		}
		return
	}
	if report != nil || err == nil {
		t.Fatalf("verify after %s: %+v, %v", outcome, report, err)
	}
	if outcome == "cancellation" {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("verify after cancellation: %v", err)
		}
	} else if !strings.Contains(err.Error(), "read fixture bad.go") {
		t.Fatalf("verify after late capture error: %v", err)
	}
}

// cancelAfterReadAt delivers the bytes and cancels the caller before returning control.
type cancelAfterReadAt struct {
	*bytes.Reader
	cancel context.CancelFunc
}

// ReadAt models cancellation during a successful non-interruptible spill read.
func (r cancelAfterReadAt) ReadAt(data []byte, offset int64) (int, error) {
	n, err := r.Reader.ReadAt(data, offset)
	r.cancel()
	return n, err
}

// TestSpillReadChecksCancellationOnReturn refuses bytes when the deadline or cancellation
// became visible during the final read and no subsequent operation would observe it.
func TestSpillReadChecksCancellationOnReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := cancelAfterReadAt{bytes.NewReader([]byte("x")), cancel}
	data, err := (capturedFixture{size: 1}).readSpill(ctx, reader)
	if data != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("spill read completed after cancellation: data=%q, err=%v", data, err)
	}
}
