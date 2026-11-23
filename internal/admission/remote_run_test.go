// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package admission

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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
