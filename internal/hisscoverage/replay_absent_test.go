package hisscoverage

import (
	"os"
	"testing"
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
