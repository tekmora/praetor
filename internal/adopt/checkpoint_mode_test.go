// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
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
	t.Run("non-shebang text permissions", func(t *testing.T) {
		testsupport.RequireCreatedMode(t, filepath.Join(repo, filepath.FromSlash(checkpointCommon)), filePerm)
	})
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
	for _, tc := range [...]struct {
		name, before, want       string
		mode, wantMode           os.FileMode
		edited, dryRun, vendored bool
	}{
		{name: "group writable", before: current, want: current, mode: 0o775, wantMode: execPerm},
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

// TestCheckpointSourceModeFollowsContent changes which bundle path starts with a shebang.
func TestCheckpointSourceModeFollowsContent(t *testing.T) {
	s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
	for _, tc := range [...]struct {
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
		if tc.mode == filePerm {
			testsupport.RequireCreatedMode(t, filepath.Join(s.repoPath, filepath.FromSlash(tc.rel)), filePerm)
		} else {
			assertCheckpointFile(t, s.repoPath, tc.rel, tc.text, tc.mode)
		}
	}
}

// TestCheckpointRefreshCancellation cancels after the shared replacement has sealed the
// new script but before it renames it over an earlier, non-executable checkpoint.
func TestCheckpointRefreshCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX execute bit")
	}
	s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
	prior := firstPriorCheckpointText(t, checkpointScript)
	current := checkpointFixtureTexts[checkpointScript]
	path := filepath.Join(s.repoPath, filepath.FromSlash(checkpointScript))
	mustWrite(t, path, prior)
	if err := os.Chmod(path, filePerm); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	observed := false
	observe := func(stage string) {
		observed = true
		assertCheckpointFile(t, s.repoPath, checkpointScript, prior, filePerm)
		assertCheckpointFile(t, filepath.Dir(stage), filepath.Base(stage), current, execPerm)
		cancel()
	}
	ctx = context.WithValue(ctx, (*contextopt.ReplaceOptions)(nil), observe)
	err := installCheckpointSource(ctx, s, checkpointSource{checkpointScript, []byte(current)}, false)
	// Either operation may win, but new bytes must already be executable.
	switch mustRead(t, path) {
	case prior:
		assertCheckpointFile(t, s.repoPath, checkpointScript, prior, filePerm)
	case current:
		assertCheckpointFile(t, s.repoPath, checkpointScript, current, execPerm)
	default:
		t.Fatal("destination holds neither complete checkpoint script")
	}
	if !observed || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation at publication, observed=%t, err=%v", observed, err)
	}
}
