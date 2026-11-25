package hisscoverage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

// maxTestBucketEntries is the documented largest certifiable listing and bounds test staging loops.
const maxTestBucketEntries = 4096

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

// TestVerifyBucketDirectoryEntryBoundary exercises the real listing limit with directory-only
// negative buckets and checks overflow reported on either read.
func TestVerifyBucketDirectoryEntryBoundary(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "backed.go", recursiveGo)
	negDir := bucketPath(root, "HISS-01", "go", bucketNegative)
	stageNumberedSubdirs(t, negDir, "dir", maxTestBucketEntries)
	t.Run("4096 directories", func(t *testing.T) {
		report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateEnforced))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !report.Passed() || report.Fixtures != 1 {
			t.Fatalf("4096 directories must pass with only the positive fixture replayed: %+v", report)
		}
	})

	const sentinel = "z-overflow"
	if err := contextopt.EnsureDirectory(t.Context(), filepath.Join(negDir, sentinel), 0o700); err != nil {
		t.Fatalf("create overflow directory: %v", err)
	}
	t.Run("4097 directories", func(t *testing.T) {
		requireDirectoryOverflow(t, t.Context(), root, sentinel)
	})
	t.Run("overflow only on second read", func(t *testing.T) {
		reads := 0
		reader := func(ctx context.Context, dir string) ([]os.DirEntry, error) {
			entries, err := readBucketEntries(ctx, dir)
			if err != nil || dir != negDir {
				return entries, err
			}
			reads++
			if reads == 1 {
				return entries[:min(len(entries), maxTestBucketEntries)], nil
			}
			return entries, nil
		}
		requireDirectoryOverflow(t, withBucketReader(t.Context(), reader), root, sentinel)
		if reads != 2 {
			t.Fatalf("negative bucket reads = %d, want 2", reads)
		}
	})
}

// requireDirectoryOverflow checks that Verify identifies the first excess directory in the negative bucket.
func requireDirectoryOverflow(t *testing.T, ctx context.Context, root, sentinel string) {
	t.Helper()
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := Finding{
		Rule: "HISS-01", Language: "go", Bucket: bucketNegative, Fixture: sentinel,
		Detail: "incomplete replay: bucket HISS-01/go/negative exceeds 4096 directory entries; report is non-certifying",
	}
	if report.Passed() || len(report.Findings) != 1 || report.Findings[0] != want {
		t.Fatalf("findings = %+v, want one incomplete replay finding: %q", report.Findings, want)
	}
}

// unknownTypeEntry wraps a DirEntry so Type reports mode and IsDir reports false, simulating
// filesystems that yield DT_UNKNOWN (fs.ModeIrregular) on directory reads.
type unknownTypeEntry struct {
	inner os.DirEntry
	mode  fs.FileMode
}

func (e unknownTypeEntry) Name() string { return e.inner.Name() }

func (e unknownTypeEntry) IsDir() bool { return false }

func (e unknownTypeEntry) Type() fs.FileMode { return e.mode }

func (e unknownTypeEntry) Info() (fs.FileInfo, error) { return e.inner.Info() }

// withBucketReader attaches a stub bucketEntryReader to ctx for deterministic replay tests.
func withBucketReader(ctx context.Context, reader bucketEntryReader) context.Context {
	return context.WithValue(ctx, bucketReaderKey{}, reader)
}

// wrapEntriesWithMode returns a bucketEntryReader that masks every entry of targetDir with mode.
func wrapEntriesWithMode(targetDir string, mode fs.FileMode) bucketEntryReader {
	return func(ctx context.Context, dir string) ([]os.DirEntry, error) {
		entries, err := readBucketEntries(ctx, dir)
		if err != nil || dir != targetDir {
			return entries, err
		}
		wrapped := make([]os.DirEntry, len(entries))
		for i := 0; i < len(entries) && i < maxBucketEntries+1; i++ {
			wrapped[i] = unknownTypeEntry{inner: entries[i], mode: mode}
		}
		return wrapped, nil
	}
}

// TestVerifyBucketUnknownTypeSubdirectoryIsSkipped verifies that a bucket subdirectory whose
// directory entry carries unknown type bits (fs.ModeIrregular) is classified via os.Lstat
// and skipped without failing or consuming the fixture bound.
func TestVerifyBucketUnknownTypeSubdirectoryIsSkipped(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	posDir := bucketPath(root, "HISS-01", "go", bucketPositive)
	subDir := filepath.Join(posDir, "nested-subdir")
	if err := contextopt.EnsureDirectory(t.Context(), subDir, 0o700); err != nil {
		t.Fatalf("create subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "ignored.go"), []byte(cleanGo), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}

	ctx := withBucketReader(t.Context(), wrapEntriesWithMode(posDir, fs.ModeIrregular))
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() || report.Fixtures != 1 {
		t.Fatalf("unknown-type subdirectory must be skipped: fixtures=%d findings=%+v", report.Fixtures, report.Findings)
	}
}

// TestVerifyBucketNonRegularEntryIsSkippedAndNamed verifies that a non-regular entry such as a
// symlink is skipped without replay and reported as not a regular fixture file, including when
// its directory entry reports unknown type bits.
func TestVerifyBucketNonRegularEntryIsSkippedAndNamed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires elevated privileges")
	}
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	posDir := bucketPath(root, "HISS-01", "go", bucketPositive)
	if err := os.Symlink(filepath.Join(posDir, "recursion.go"), filepath.Join(posDir, "alias.go")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	ctx := withBucketReader(t.Context(), wrapEntriesWithMode(posDir, fs.ModeIrregular))
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() || report.Fixtures != 1 || len(report.Findings) != 1 {
		t.Fatalf("want 1 replayed fixture and 1 non-regular finding, got fixtures=%d findings=%+v",
			report.Fixtures, report.Findings)
	}
	got := report.Findings[0]
	if got.Fixture != "alias.go" || !strings.Contains(got.Detail, "not a regular fixture file") {
		t.Fatalf("finding = %q, want alias.go named as not a regular fixture file", got)
	}
}

// TestVerifyBucketUnknownTypeRegularFilesRespectBound verifies that regular files whose
// directory entries report fs.ModeIrregular still count toward maxFixturesPerBucket.
func TestVerifyBucketUnknownTypeRegularFilesRespectBound(t *testing.T) {
	root := t.TempDir()
	posDir := bucketPath(root, "HISS-01", "go", bucketPositive)
	stageNumberedFixtures(t, posDir, "rec", recursiveGo, maxFixturesPerBucket+1)

	ctx := withBucketReader(t.Context(), wrapEntriesWithMode(posDir, fs.ModeIrregular))
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() || len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "incomplete replay") {
		t.Fatalf("257 unknown-type regular files must fail as incomplete, got %+v", report.Findings)
	}
}

// TestVerifyBucketFileAddedDuringReplayIsIncomplete verifies that a regular file added to a
// bucket after its initial listing and before the post-replay re-read fails Verify with an
// incomplete-replay finding naming the bucket.
func TestVerifyBucketFileAddedDuringReplayIsIncomplete(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	posDir := bucketPath(root, "HISS-01", "go", bucketPositive)

	reads := 0
	reader := func(ctx context.Context, dir string) ([]os.DirEntry, error) {
		entries, err := readBucketEntries(ctx, dir)
		if err != nil || dir != posDir {
			return entries, err
		}
		reads++
		if reads == 1 {
			if writeErr := os.WriteFile(filepath.Join(posDir, "z-added.go"), []byte(recursiveGo), 0o600); writeErr != nil {
				t.Fatalf("stage added fixture: %v", writeErr)
			}
		}
		return entries, nil
	}

	report, err := Verify(withBucketReader(t.Context(), reader), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if reads != 2 {
		t.Fatalf("bucket reads = %d, want initial read plus post-replay re-read", reads)
	}
	assertAddedFixtureIncomplete(t, report)
}

// assertAddedFixtureIncomplete checks the one incomplete-replay finding a bucket changed during
// the replay records for the added fixture.
func assertAddedFixtureIncomplete(t *testing.T, report *Report) {
	t.Helper()
	if report.Passed() || len(report.Findings) != 1 {
		t.Fatalf("bucket mutation must record 1 incomplete finding, got %+v", report.Findings)
	}
	got := report.Findings[0]
	if got.Fixture != "z-added.go" || !strings.Contains(got.Detail, "incomplete replay") ||
		!strings.Contains(got.Detail, "HISS-01/go/positive") {
		t.Fatalf("finding = %q, want incomplete replay naming HISS-01/go/positive and z-added.go", got)
	}
}

// TestVerifyBucketFileRemovedDuringReplayIsIncomplete verifies that removing a replayed regular
// file before the post-replay re-read also records an incomplete-replay finding.
func TestVerifyBucketFileRemovedDuringReplayIsIncomplete(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "a-first.go", recursiveGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketPositive, "b-second.go", recursiveGo)
	posDir := bucketPath(root, "HISS-01", "go", bucketPositive)

	reads := 0
	reader := func(ctx context.Context, dir string) ([]os.DirEntry, error) {
		if dir == posDir {
			reads++
			if reads == 2 {
				if rmErr := os.Remove(filepath.Join(posDir, "b-second.go")); rmErr != nil {
					t.Fatalf("remove replayed fixture: %v", rmErr)
				}
			}
		}
		return readBucketEntries(ctx, dir)
	}

	report, err := Verify(withBucketReader(t.Context(), reader), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() || len(report.Findings) != 1 || report.Findings[0].Fixture != "b-second.go" ||
		!strings.Contains(report.Findings[0].Detail, "incomplete replay") {
		t.Fatalf("removed fixture must fail as incomplete naming b-second.go, got %+v", report.Findings)
	}
}

// TestVerifyBucketListedFileBecomesDirectoryIsIncomplete replaces a listed regular fixture
// before classification and requires Verify to identify the changed bucket and fixture.
func TestVerifyBucketListedFileBecomesDirectoryIsIncomplete(t *testing.T) {
	const fixture = "clean.go"
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, fixture, cleanGo)
	negDir := bucketPath(root, "HISS-01", "go", bucketNegative)
	swapped := false
	reader := func(ctx context.Context, dir string) ([]os.DirEntry, error) {
		entries, err := readBucketEntries(ctx, dir)
		if err != nil || dir != negDir || swapped {
			return entries, err
		}
		path := filepath.Join(dir, fixture)
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove listed fixture: %v", err)
		}
		if err := contextopt.EnsureDirectory(ctx, path, 0o700); err != nil {
			t.Fatalf("replace listed fixture with directory: %v", err)
		}
		swapped = true
		return entries, nil
	}

	report, err := Verify(withBucketReader(t.Context(), reader), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() || len(report.Findings) != 1 {
		t.Fatalf("replacing a listed fixture must fail with one finding, got %+v", report)
	}
	want := Finding{
		Rule: "HISS-01", Language: "go", Bucket: bucketNegative, Fixture: fixture,
		Detail: "incomplete replay: bucket HISS-01/go/negative changed during verification; report is non-certifying",
	}
	if got := report.Findings[0]; got != want {
		t.Fatalf("finding = %q, want %q", got, want)
	}
}
