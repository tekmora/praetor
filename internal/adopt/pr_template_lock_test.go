// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

// templateFixtureRoot pins a fixture directory until the test ends.
func templateFixtureRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	root, err := contextopt.OpenDirectory(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

// takeTemplateFixtureLock holds the directory until release or test cleanup.
func takeTemplateFixtureLock(t *testing.T, path string) func() {
	t.Helper()
	unlock, err := contextopt.LockDirectory(t.Context(), templateFixtureRoot(t, path))
	if err != nil {
		t.Fatal(err)
	}
	release := sync.OnceFunc(func() {
		if err := unlock(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(release)
	return release
}

// TestPRTemplateRenamedCheckout queues an adoption before the checkout name is reused.
func TestPRTemplateRenamedCheckout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support renaming the open checkout in this fixture")
	}
	for _, name := range []string{"create", "refresh uppercase"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				checkRenamedTemplateCheckout(t, name == "refresh uppercase")
			})
		})
	}
}

// checkRenamedTemplateCheckout changes the locked tree while the waiter is blocked, then
// checks both the original checkout's result and the entire replacement directory.
func checkRenamedTemplateCheckout(t *testing.T, refresh bool) {
	t.Helper()
	repo := t.TempDir()
	moved := filepath.Join(t.TempDir(), "original")
	s := ceilingPRTemplateSession(repo)
	release := takeTemplateFixtureLock(t, repo)
	done := make(chan error, 1)
	go func() { done <- reconcilePullRequestTemplate(t.Context(), s) }()
	synctest.Wait()
	select {
	case err := <-done:
		t.Fatalf("adoption returned before lock release: %v", err)
	default:
	}

	if err := os.Rename(repo, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(repo, workingDirPerm); err != nil {
		t.Fatal(err)
	}
	rel := prTemplateFile
	if refresh {
		rel = prTemplateUpper
		prior := ceilingPRTemplateSession(moved)
		prior.policy.Policy.Complexity.MaxCyclomatic = 8
		text := buildPullRequestTemplate(prior.policy.Policy.Complexity)
		mustWrite(t, filepath.Join(moved, rel), text)
		mustWrite(t, filepath.Join(moved, workingDirPath, "adopt-installed", rel+".sha256"), fixtureDigest(t, rel, []byte(text))+"\n")
	}
	release()
	synctest.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("adoption remained blocked after lock release")
	}
	assertDirEmpty(t, repo)
	want := buildPullRequestTemplate(s.policy.Policy.Complexity)
	if got := repoText(t, moved, rel); got != want {
		t.Fatal("original checkout did not receive the requested template")
	}
	record := filepath.Join(moved, workingDirPath, "adopt-installed", rel+".sha256")
	if got := mustRead(t, record); got != fixtureDigest(t, rel, []byte(want))+"\n" {
		t.Fatalf("original checkout has the wrong install record: %q", got)
	}
}

// TestPRTemplateRefusesLinkedGitHub refuses the scaffold before writing through an in-tree link.
func TestPRTemplateRefusesLinkedGitHub(t *testing.T) {
	s := ceilingPRTemplateSession(t.TempDir())
	target := linkInRootDir(t, s.repoPath, ".github", "target")
	err := reconcilePullRequestTemplate(t.Context(), s)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a named symlink refusal, got %v", err)
	}
	assertDirEmpty(t, target)
	assertAbsent(t, s.repoPath, workingDirPath)
}

// TestPRTemplateDefaultLockBudget checks the wrapper's own timeout against an in-process holder.
func TestPRTemplateDefaultLockBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := ceilingPRTemplateSession(t.TempDir())
		mustWrite(t, filepath.Join(s.repoPath, prTemplateFile), "original template\n")
		record := filepath.Join(s.repoPath, workingDirPath, "adopt-installed", prTemplateFile+".sha256")
		mustWrite(t, record, "invalid digest\n")
		takeTemplateFixtureLock(t, s.repoPath)
		before := snapshotTree(t, s.repoPath)
		ctx := t.Context()
		if _, limited := ctx.Deadline(); limited {
			t.Fatal("fixture supplied a deadline to adoption")
		}
		start := time.Now()
		err := reconcilePullRequestTemplate(ctx, s)
		if elapsed := time.Since(start); elapsed != contextopt.DirectoryLockBudget {
			t.Errorf("lock refusal took %s, want %s", elapsed, contextopt.DirectoryLockBudget)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected a deadline refusal, got %v", err)
		}
		for _, want := range [...]string{
			"PR template adoption lock", "another writer in this process",
			contextopt.DirectoryLockBudget.String() + " wait budget",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("lock refusal %q lacks %q", err, want)
			}
		}
		assertTreeUnchanged(t, before, snapshotTree(t, s.repoPath))
	})
}
