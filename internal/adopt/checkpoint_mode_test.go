// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/testsupport"
)

// assertCheckpointFile checks the installed bytes on every platform and the POSIX mode where supported.
func assertCheckpointFile(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if got := mustRead(t, path); got != content {
		t.Errorf("%s content differs from the expected checkpoint text", rel)
	}
	if runtime.GOOS == "windows" {
		t.Log("skipping file mode assertion on Windows, which has no POSIX execute bit")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode(); got != mode {
		t.Errorf("%s mode = %04o, want %04o", rel, got, mode)
	}
}

// commitCheckpointMode checks the mode Git recorded after committing the fixture.
func commitCheckpointMode(t *testing.T, repo, want string) {
	t.Helper()
	commitAll(t, repo)
	if runtime.GOOS == "windows" {
		t.Log("skipping Git mode assertion on Windows, where Git cannot infer a POSIX execute bit")
		return
	}
	entry := fixtureGit(t, repo, "ls-files", "--stage", "--", checkpointScript)
	if !strings.HasPrefix(entry, want+" ") {
		t.Errorf("checkpoint.py index entry = %q, want mode %s", entry, want)
	}
}

// TestAdopt_CheckpointSourceModes checks a fresh adoption and re-adoption of its exact bytes
// after committing the historical 100644 mode.
func TestAdopt_CheckpointSourceModes(t *testing.T) {
	repo, source := t.TempDir(), checkpointLockSource(t)
	testsupport.InitGitRepoWithOrigin(t, repo, "https://github.com/acme/widget.git")
	opts := AdoptOptions{SkipHookActivation: true}
	readoptWith(t, repo, source, opts)
	assertCheckpointFile(t, repo, checkpointScript, checkpointFixtureTexts[checkpointScript], execPerm)
	assertCheckpointFile(t, repo, checkpointLauncher, checkpointFixtureTexts[checkpointLauncher], execPerm)
	assertCheckpointFile(t, repo, checkpointCommon, checkpointFixtureTexts[checkpointCommon], filePerm)
	commitCheckpointMode(t, repo, "100755")

	if err := os.Chmod(filepath.Join(repo, filepath.FromSlash(checkpointScript)), filePerm); err != nil {
		t.Fatal(err)
	}
	commitCheckpointMode(t, repo, "100644")
	readoptWith(t, repo, source, opts)
	assertCheckpointFile(t, repo, checkpointScript, checkpointFixtureTexts[checkpointScript], execPerm)
	commitCheckpointMode(t, repo, "100755")
}

// TestCheckpointSourceModeRefresh exercises the scaffold's ownership decision before it can
// change a file's bytes or mode. A dry run leaves the planted mode for a live run to repair.
func TestCheckpointSourceModeRefresh(t *testing.T) {
	source := checkpointSource{checkpointScript, []byte(checkpointFixtureTexts[checkpointScript])}
	current := string(source.data)
	prior := firstPriorCheckpointText(t, checkpointScript)
	for _, tc := range []struct {
		name, before, want       string
		mode, wantMode           os.FileMode
		edited, dryRun, vendored bool
	}{
		{name: "earlier text", before: prior, want: current, mode: filePerm, wantMode: execPerm},
		{name: "current CRLF", before: crlfText(current), want: crlfText(current), mode: filePerm, wantMode: execPerm},
		{name: "edited script", before: current + "# edit\n", want: current + "# edit\n", mode: 0o640, wantMode: 0o640, edited: true},
		{name: "dry run", before: current, want: current, mode: filePerm, wantMode: filePerm, dryRun: true},
		{name: "matching vendored script", before: current, want: current, mode: filePerm, wantMode: execPerm, vendored: true},
		{name: "earlier vendored script", before: prior, want: prior, mode: filePerm, wantMode: filePerm, vendored: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
			path := filepath.Join(s.repoPath, filepath.FromSlash(checkpointScript))
			mustWrite(t, path, tc.before)
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			s.opts = AdoptOptions{Force: tc.edited, DryRun: tc.dryRun}
			err := installCheckpointSource(t.Context(), s, source, tc.vendored)
			if (err != nil) != tc.edited {
				t.Fatalf("installCheckpointSource returned %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "differs from the verified checkpoint evaluator") {
				t.Fatalf("expected an edited checkpoint refusal, got %v", err)
			}
			assertCheckpointFile(t, s.repoPath, checkpointScript, tc.want, tc.wantMode)
		})
	}
}

// TestCheckpointModeRepairKeepsFile checks the inode and mtime across a mode-only
// repair of a CRLF checkout. Special bits are planted independently of group write.
func TestCheckpointModeRepairKeepsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX execute or special mode bits")
	}
	for _, tc := range [...]struct {
		rel    string
		before os.FileMode
		want   os.FileMode
	}{
		{checkpointScript, filePerm, execPerm},
		{checkpointScript, 0o775, execPerm},
		{checkpointScript, os.ModeSetuid | execPerm, execPerm},
		{checkpointCommon, 0o666, filePerm},
		{checkpointCommon, os.ModeSetgid | os.ModeSticky | filePerm, filePerm},
	} {
		t.Run(tc.rel+"/"+tc.before.String(), func(t *testing.T) {
			s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
			text := crlfText(checkpointFixtureTexts[tc.rel])
			path := filepath.Join(s.repoPath, filepath.FromSlash(tc.rel))
			mustWrite(t, path, text)
			before := plantCheckpointMode(t, path, tc.before)
			source := checkpointSource{tc.rel, []byte(checkpointFixtureTexts[tc.rel])}
			if err := installCheckpointSource(t.Context(), s, source, false); err != nil {
				t.Fatal(err)
			}
			assertCheckpointFile(t, s.repoPath, tc.rel, text, tc.want)
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("repair of %s at %v changed inode or mtime: %v, %v", tc.rel, tc.before, after, err)
			}
		})
	}
}

// plantCheckpointMode sets a distinct mtime and verifies the starting mode, including special bits.
func plantCheckpointMode(t *testing.T, path string, mode os.FileMode) os.FileInfo {
	t.Helper()
	stamp := time.Unix(1000000000, 0)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode() != mode {
		t.Fatalf("plant %v on %s: stat %v, error %v", mode, path, info, err)
	}
	return info
}

// TestCheckpointSourceModeFollowsContent changes which bundle path starts with a shebang.
func TestCheckpointSourceModeFollowsContent(t *testing.T) {
	s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
	for _, tc := range []struct {
		rel, text string
		mode      os.FileMode
	}{
		{checkpointCommon, "#!/usr/bin/env python3\n", execPerm},
		{checkpointScript, "# comment\n#!/usr/bin/env python3\n", filePerm},
	} {
		source := checkpointSource{tc.rel, []byte(tc.text)}
		if err := installCheckpointSource(t.Context(), s, source, false); err != nil {
			t.Fatal(err)
		}
		assertCheckpointFile(t, s.repoPath, tc.rel, tc.text, tc.mode)
	}
}
