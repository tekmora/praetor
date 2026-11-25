// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/testsupport"
	"github.com/cordanaLLM/praetor/internal/util"
)

// TestDocstringsClosedOutput checks both entry points with passing coverage and a failed report write.
func TestDocstringsClosedOutput(t *testing.T) {
	dir := t.TempDir()
	testsupport.InitGitRepoWithOrigin(t, dir, ".")
	base := testsupport.RunFixtureGit(t, dir,
		[]string{"commit", "--allow-empty", "-m", "base"}, []string{"rev-parse", "HEAD"})
	head := testsupport.RunFixtureGit(t, dir,
		[]string{"commit", "--allow-empty", "-m", "head"}, []string{"rev-parse", "HEAD"})
	ctx, err := util.WithCommandEnvironment(t.Context(), testsupport.HermeticGitEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	t.Cleanup(func() { os.Stdout = original })
	os.Stdout = closed
	if err := runDocstringsRange(ctx, dir, base, head, nil); !errors.Is(err, os.ErrClosed) {
		t.Errorf("range: got %v, want closed output error", err)
	}
	line := "refs/heads/topic " + head + " refs/heads/topic " + base + "\n"
	if err := runDocstringsPrePush(ctx, dir, nil, strings.NewReader(line)); !errors.Is(err, os.ErrClosed) {
		t.Errorf("pre-push: got %v, want closed output error", err)
	}
	for _, input := range []string{"", "refs/heads/topic " + head + " refs/heads/topic " + strings.Repeat("0", len(head)) + "\n"} {
		err := runDocstringsPrePush(ctx, dir, nil, strings.NewReader(input))
		if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "skip diagnostic") {
			t.Errorf("skipped pre-push %q: got %v, want closed skip diagnostic", input, err)
		}
	}
}
