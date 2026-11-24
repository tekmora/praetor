package hisscoverage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

// maxTestBucketEntries bounds fixture and subdirectory staging loops in bucket tests (HISS-02).
const maxTestBucketEntries = 512

// stageNumberedFixtures writes count regular Go fixtures named <prefix>-NNN.go inside bucketDir.
func stageNumberedFixtures(t *testing.T, bucketDir, prefix, body string, count int) {
	t.Helper()
	if err := contextopt.EnsureDirectory(t.Context(), bucketDir, 0o700); err != nil {
		t.Fatalf("create fixture bucket: %v", err)
	}
	for i := 0; i < count && i < maxTestBucketEntries; i++ {
		name := fmt.Sprintf("%s-%03d.go", prefix, i)
		if err := os.WriteFile(filepath.Join(bucketDir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
}

// stageNumberedSubdirs creates count subdirectories named <prefix>-NNN inside bucketDir.
func stageNumberedSubdirs(t *testing.T, bucketDir, prefix string, count int) {
	t.Helper()
	for i := 0; i < count && i < maxTestBucketEntries; i++ {
		sub := filepath.Join(bucketDir, fmt.Sprintf("%s-%03d", prefix, i))
		if err := contextopt.EnsureDirectory(t.Context(), sub, 0o700); err != nil {
			t.Fatalf("create subdirectory %s: %v", sub, err)
		}
	}
}

// bucketPath returns the path to one rule/language/bucket directory under root.
func bucketPath(root, rule, lang, bucket string) string {
	return filepath.Join(root, filepath.FromSlash(FixtureDir), rule, lang, bucket)
}

// verifyPassingBucketCount stages count positive HISS-01 Go fixtures and asserts that Verify
// replays all count regular files and certifies the claim.
func verifyPassingBucketCount(t *testing.T, count int) {
	t.Helper()
	root := t.TempDir()
	stageNumberedFixtures(t, bucketPath(root, "HISS-01", "go", bucketPositive), "rec", recursiveGo, count)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() {
		t.Fatalf("%d-file bucket must pass: %+v", count, report.Findings)
	}
	if report.Claims != 1 || report.Fixtures != count {
		t.Fatalf("Claims/Fixtures = %d/%d, want 1/%d", report.Claims, report.Fixtures, count)
	}
}

// TestVerifyBucketControlThreeRegularFilesPasses is the passing control case: a three-file
// bucket well below maxFixturesPerBucket replays every fixture and certifies the claim.
func TestVerifyBucketControlThreeRegularFilesPasses(t *testing.T) {
	verifyPassingBucketCount(t, 3)
}

// TestVerifyBucketBoundaryAt256RegularFilesPasses is the upper pass boundary: a bucket with
// exactly maxFixturesPerBucket (256) regular files replays every fixture and passes.
func TestVerifyBucketBoundaryAt256RegularFilesPasses(t *testing.T) {
	verifyPassingBucketCount(t, maxFixturesPerBucket)
}

// TestVerifyBucketPast256RegularFilesIsIncomplete is the negative overflow boundary: a 257th
// regular file exceeds maxFixturesPerBucket and must fail Verify with a visible incomplete
// replay finding naming the bucket rather than certifying a truncated scan.
func TestVerifyBucketPast256RegularFilesIsIncomplete(t *testing.T) {
	root := t.TempDir()
	stageNumberedFixtures(t, bucketPath(root, "HISS-01", "go", bucketPositive), "rec", recursiveGo, maxFixturesPerBucket+1)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("a 257-file bucket must fail Verify as an incomplete, non-certifying replay")
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings = %+v, want 1 incomplete-replay finding", report.Findings)
	}
	finding := report.Findings[0]
	if finding.Bucket != bucketPositive || !strings.Contains(finding.Detail, "incomplete replay") ||
		!strings.Contains(finding.Detail, "HISS-01/go/positive") {
		t.Fatalf("finding must report incomplete replay and name the bucket, got %q", finding)
	}
}

// TestVerifyBucketDirectoriesDoNotConsumeFixtureBound verifies that subdirectories neither
// consume maxFixturesPerBucket nor replay nested files: a violating regular file sorted after
// 260 subdirectories is still scanned and fails Verify, while a file inside a subdirectory is
// ignored.
func TestVerifyBucketDirectoriesDoNotConsumeFixtureBound(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "backed.go", recursiveGo)
	negDir := bucketPath(root, "HISS-01", "go", bucketNegative)
	stageNumberedSubdirs(t, negDir, "dir", maxFixturesPerBucket+4)
	nested := filepath.Join(negDir, "dir-000", "nested.go")
	if err := os.WriteFile(nested, []byte(recursiveGo), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	violating := filepath.Join(negDir, "z-overmatch.go")
	if err := os.WriteFile(violating, []byte(recursiveGo), 0o600); err != nil {
		t.Fatalf("write violating fixture: %v", err)
	}

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("subdirectories ahead of z-overmatch.go hid a violating negative fixture")
	}
	if report.Fixtures != 2 || len(report.Findings) != 1 || report.Findings[0].Fixture != "z-overmatch.go" {
		t.Fatalf("Fixtures=%d Findings=%+v, want 2 regular fixtures and over-match on z-overmatch.go",
			report.Fixtures, report.Findings)
	}
}
