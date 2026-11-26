package hisscoverage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

// TestReplayBucketDistinguishesAbsentFromMisplaced: a claim may have no bucket, but a regular
// file where a bucket directory belongs must not be replayed as an empty bucket. On Windows the
// read reports not-exist for both, which made the misplaced bucket silently count as empty.
func TestReplayBucketDistinguishesAbsentFromMisplaced(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	catalog := catalogFor("HISS-01", "go", StateEnforced)
	if report, err := Verify(t.Context(), root, catalog); err != nil || !report.Passed() || report.Fixtures != 1 {
		t.Fatalf("absent bucket was not empty: %v %v", report, err)
	}
	if err := os.WriteFile(bucketPath(root, "HISS-01", "go", bucketNegative), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(t.Context(), root, catalog); err == nil {
		t.Fatal("a regular file was replayed as an empty bucket")
	}
}

// TestCorpusOpenFailurePreservesCleanup checks both shapes produced by the component
// walk when the child is missing: a successful parent close and a failed parent close.
func TestCorpusOpenFailurePreservesCleanup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(FixtureDir))
	_, missing := os.Stat(path)
	if !errors.Is(missing, os.ErrNotExist) {
		t.Fatalf("missing corpus fixture: %v", missing)
	}
	if !util.DirectoryAbsent(path, errors.Join(missing, nil)) {
		t.Fatalf("corpus with a sole missing component: %v", missing)
	}
	cleanup := &os.PathError{Op: "close", Path: root, Err: os.ErrPermission}
	err := fmt.Errorf("walk: %w", errors.Join(missing, cleanup))
	if util.DirectoryAbsent(path, err) {
		t.Fatalf("accepted an empty fixture corpus after failed cleanup: %v", err)
	}
}

// TestMissingCorpusSharesParentCancellation cancels the unbounded parent when
// absence inspection requests its own deadline after the failed open.
func TestMissingCorpusSharesParentCancellation(t *testing.T) {
	requireNativeReplay(t)
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &cancelOnAbsenceCheck{Context: parent, cancel: cancel}
	var store fixtureStore
	corpus, err := store.openCorpusSnapshot(ctx, t.TempDir(), catalogFor("HISS-01", "go", StateEnforced))
	if corpus != nil || !errors.Is(err, os.ErrNotExist) || !errors.Is(err, context.Canceled) {
		t.Fatalf("missing corpus after cancellation: corpus=%v err=%v", corpus, err)
	}
}

// cancelOnAbsenceCheck models an unbounded parent at the two independent I/O scopes.
type cancelOnAbsenceCheck struct {
	context.Context
	cancel context.CancelFunc
	scopes int
}

// Deadline admits the open and cancels when the ancestor walk derives its bound.
func (c *cancelOnAbsenceCheck) Deadline() (time.Time, bool) {
	c.scopes++
	if c.scopes == 2 {
		c.cancel()
	}
	return time.Time{}, false
}
