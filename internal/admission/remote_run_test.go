// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package admission

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

// TestRunRemoteSnapshot_CancelClosesLease proves SSH stays open for cleanup after cancellation.
func TestRunRemoteSnapshot_CancelClosesLease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake SSH requires a POSIX shell")
	}
	bin := t.TempDir()
	// nosemgrep: go_file-permissions_rule-fileperm, go.lang.correctness.permissions.file_permission.incorrect-default-permission -- SSH stub needs the owner execute bit
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(cancelLeaseSSH), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	bundle, err := os.CreateTemp(t.TempDir(), "bundle")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bundle.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	executor := Executor{Name: "fixture", SSHHost: "fixture", SSHUser: "fixture"}
	step := Step{Stdout: cancelOnSSHReady(cancel), Stderr: &stderr}
	code, err := runRemoteSnapshot(ctx, executor, step, gitSnapshot{}, bundle, time.Minute, 1, 1)
	if code != 0 || !errors.Is(err, context.Canceled) || stderr.String() != "remote cleanup complete\n" {
		t.Fatalf("cancelled SSH = (%d, %v), stderr %q", code, err, stderr.String())
	}
}

type cancelOnSSHReady context.CancelFunc

func (cancel cancelOnSSHReady) Write(p []byte) (int, error) {
	cancel()
	return len(p), nil
}

const cancelLeaseSSH = `#!/bin/sh
printf 'ready\n'
if IFS= read -r unexpected; then exit 2; fi
printf 'remote cleanup complete\n' >&2
`

// TestRemoteWorkspace_LeaseEOFInCheckoutPreventsLaunch closes the lease during git read-tree.
func TestRemoteWorkspace_LeaseEOFInCheckoutPreventsLaunch(t *testing.T) {
	script := replaceWorkspaceLine(t, remoteWorkspaceScript, `git read-tree --reset -u "$tree"`,
		"exec </dev/null")
	script = replaceWorkspaceLine(t, script, `( IFS= read -r unused <&3 || kill -TERM "$parent" ) &`,
		`( sleep 1; IFS= read -r unused <&3 || kill -TERM "$parent" ) &`)
	script = replaceWorkspaceLine(t, script, `"$@" </dev/null 3<&- &
runner=$!`, `sleep 0.1
"$@" </dev/null 3<&- &
runner=$!
sleep 0.1`)
	runWorkspaceFixture(t, script, "echo 'step started'; exec sleep 10")
}

// TestRemoteWorkspace_TermDuringPIDPublication checks for live children after wrapper cleanup.
func TestRemoteWorkspace_TermDuringPIDPublication(t *testing.T) {
	for _, child := range []string{"watcher", "runner"} {
		t.Run(child, func(t *testing.T) {
			record := child + "=$!"
			script := replaceWorkspaceLine(t, remoteWorkspaceScript, record,
				`printf '%s\n' "$!" > "$FIXTURE_CHILD_PID"
kill -TERM "$parent"
`+record)
			runWorkspaceFixture(t, script, "exec sleep 10")
		})
	}
}

// replaceWorkspaceLine inserts fixture behavior at a specific point in the remote wrapper.
func replaceWorkspaceLine(t *testing.T, script, original, replacement string) string {
	t.Helper()
	if strings.Count(script, original) != 1 {
		t.Fatalf("fixture insertion point not unique: %q", original)
	}
	return strings.Replace(script, original, replacement, 1)
}

// runWorkspaceFixture runs the real workspace wrapper with stub Git and a live stdin lease.
func runWorkspaceFixture(t *testing.T, script, step string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("workspace wrapper requires sh: %v", err)
	}
	root, fixture := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(fixture, "memory.max"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, lease, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(input.Close(), lease.Close()); err != nil {
			t.Error(err)
		}
	})
	env := util.FilterEnvironment(os.Environ(), func(name string) bool {
		return strings.HasPrefix(strings.ToUpper(name), "GIT_")
	})
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ctx, err = util.WithCommandEnvironment(ctx, append(env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"PRAETOR_ADMIT_CGROUP_DIR="+fixture, "FIXTURE_CHILD_PID="+filepath.Join(fixture, "child.pid")))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = util.RunCommandPassthrough(ctx, "", "sh", input, &output, &output, "-c", workspaceFixtureDriver,
		"driver", "git() { :; }\n"+script, "workspace", "fixture", root, "0", "sha1", "head", "tree", ".", "1", "1",
		"sh", "-c", step)
	if files, err := os.ReadDir(root); err != nil || len(files) != 0 {
		t.Fatalf("workspace was not cleaned: %v, %v", files, err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 143 || output.Len() != 0 {
		t.Fatalf("workspace cancellation: %v, output %q", err, output.String())
	}
}

const workspaceFixtureDriver = `
script=$1
shift
sh -c "$script" "$@"
rc=$?
if [ -s "$FIXTURE_CHILD_PID" ]; then
    IFS= read -r pid < "$FIXTURE_CHILD_PID"
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || :
        echo 'fixture child still alive' >&2
        exit 1
    fi
fi
exit "$rc"
`
