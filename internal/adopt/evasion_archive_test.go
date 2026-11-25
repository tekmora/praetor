package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/util"
)

// TestEvasionArchiveRejectsEscapeDigests checks existing and absent outside archives,
// so both the read and write paths must refuse traversal without touching outside bytes.
func TestEvasionArchiveRejectsEscapeDigests(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "existing"}[existing], func(t *testing.T) {
			assertEvasionArchiveEscapeRejected(t, existing)
		})
	}
}

// assertEvasionArchiveEscapeRejected checks refusal and outside bytes for one archive state.
func assertEvasionArchiveEscapeRejected(t *testing.T, existing bool) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "fixtures")
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a directory needs the owner search bit to hold entries
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "x.block_evasion.py")
	const previous = "outgoing rendering\r\n"
	if existing {
		mustWrite(t, outside, previous)
	}
	for _, digest := range []string{"../x", filepath.Join(parent, "x")} {
		if err := archiveEvasionRendering(dir, digest, previous); err == nil {
			t.Errorf("escaping digest %q accepted", digest)
		}
	}
	data, err := readFixtureFile(parent, filepath.Base(outside))
	if existing {
		if err != nil || string(data) != previous {
			t.Errorf("outside archive changed: %q, %v", data, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("outside archive created or unreadable: %q, %v", data, err)
	}
}

// TestEvasionArchiveRejectsEscapingSymlinks refuses an ordinary hex name whose archive
// is a link outside the fixture directory, preserving both the link and its target bytes.
func TestEvasionArchiveRejectsEscapingSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs developer mode on Windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.py")
	const previous = "outgoing rendering\n"
	mustWrite(t, outside, previous)
	digest := strings.Repeat("b", 64)
	archive := filepath.Join(dir, digest+".block_evasion.py")
	if err := os.Symlink(outside, archive); err != nil {
		t.Fatal(err)
	}
	if err := archiveEvasionRendering(dir, digest, previous); err == nil {
		t.Error("escaping archive symlink accepted")
	}
	assertFixtureSymlinkUnchanged(t, archive, outside, previous)
}

// assertFixtureSymlinkUnchanged checks the link destination and the bytes at that destination.
func assertFixtureSymlinkUnchanged(t *testing.T, link, outside, previous string) {
	t.Helper()
	if got := mustRead(t, outside); got != previous {
		t.Errorf("outside bytes changed: %q", got)
	}
	if got, err := os.Readlink(link); err != nil || got != outside {
		t.Errorf("fixture link changed: %q, %v", got, err)
	}
}

// TestEvasionUpdateRejectsEscapingCurrentFixture exercises the fixture updater in a temporary checkout.
func TestEvasionUpdateRejectsEscapingCurrentFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs developer mode on Windows")
	}
	checkout := t.TempDir()
	dir := filepath.Join(checkout, priorEvasionFixtures)
	outside := filepath.Join(checkout, "outside.py")
	const previous = "outgoing rendering\n"
	mustWrite(t, outside, previous)
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a directory needs the owner search bit to hold entries
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, currentEvasionFixture)
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(updateEmittedFixturesEnv, "1")
	out, err := util.RunCommand(t.Context(), checkout, exe, "-test.run=^TestEmittedHookFixturesMatchTheRendering$")
	if err == nil || !strings.Contains(out, "read "+currentEvasionFixture) {
		t.Errorf("want refusal reading the current fixture, got %v: %s", err, out)
	}
	assertFixtureSymlinkUnchanged(t, link, outside, previous)
	archive := fixtureDigest(t, "outside", []byte(previous)) + ".block_evasion.py"
	if _, err := os.Stat(filepath.Join(dir, archive)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("outside bytes archived or archive unreadable: %v", err)
	}
}

// TestEvasionUpdateNormalizesCurrentFixture writes the rendered bytes without archiving a checkout-only difference.
func TestEvasionUpdateNormalizesCurrentFixture(t *testing.T) {
	current := buildBlockEvasionPY()
	t.Chdir(t.TempDir())
	path := filepath.Join(priorEvasionFixtures, currentEvasionFixture)
	mustWrite(t, path, crlfText(current))
	updateEvasionRenderingFixtures(t, current)
	if got := mustRead(t, path); got != current {
		t.Error("current fixture differs from the rendered bytes")
	}
	if files := readFixtureDir(t, priorEvasionFixtures); len(files) != 1 {
		t.Errorf("line-ending change created an archive in %s", priorEvasionFixtures)
	}
}

// TestPriorFixtureReadConfinesComputedNames verifies the shared reader accepts a normal
// name and refuses traversal, absolute names, and an escaping link without changing bytes.
func TestPriorFixtureReadConfinesComputedNames(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "fixtures")
	mustWrite(t, filepath.Join(dir, "normal"), "inside\n")
	outside := filepath.Join(parent, "outside")
	mustWrite(t, outside, "outside\n")
	if got, err := readFixtureFile(dir, "normal"); err != nil || string(got) != "inside\n" {
		t.Fatalf("normal fixture: %q, %v", got, err)
	}
	names := []string{"../outside", outside}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
			t.Fatal(err)
		}
		names = append(names, "linked")
	}
	for _, name := range names {
		if got, err := readFixtureFile(dir, name); err == nil || len(got) != 0 {
			t.Errorf("escaping fixture %q read: %q, %v", name, got, err)
		}
	}
	if got := mustRead(t, outside); got != "outside\n" {
		t.Errorf("outside bytes changed: %q", got)
	}
}

// TestEvasionArchivePreservesHexDigestBytes verifies creation, line-ending equivalence,
// mismatch refusal, and preservation of the original bytes for a normal digest.
func TestEvasionArchivePreservesHexDigestBytes(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("a", 64)
	const previous = "outgoing rendering\r\n"
	for _, text := range []string{previous, "outgoing rendering\n"} {
		if err := archiveEvasionRendering(dir, digest, text); err != nil {
			t.Fatal(err)
		}
	}
	if err := archiveEvasionRendering(dir, digest, "different\n"); err == nil {
		t.Error("mismatched archive accepted")
	}
	path := filepath.Join(dir, digest+".block_evasion.py")
	if got := mustRead(t, path); got != previous {
		t.Errorf("archive bytes = %q, want %q", got, previous)
	}
	const mixed = "first line\r\nsecond line\n"
	mustWrite(t, path, mixed)
	if err := archiveEvasionRendering(dir, digest, "first line\nsecond line\n"); err == nil || !strings.Contains(err.Error(), "mixed LF and CRLF") {
		t.Errorf("want mixed line-ending error, got %v", err)
	}
	if got := mustRead(t, path); got != mixed {
		t.Errorf("mixed archive bytes = %q, want %q", got, mixed)
	}
}
