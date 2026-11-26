// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReconcileExecutableIn_KeepsXattr checks a user attribute across a byte-identical mode repair.
func TestReconcileExecutableIn_KeepsXattr(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run")
	data := []byte("#!/bin/sh\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	const attr, value = "user.praetor_fixture", "keep"
	err := syscall.Setxattr(path, attr, []byte(value), 0)
	if errors.Is(err, syscall.ENOTSUP) {
		t.Skip("fixture filesystem does not support user extended attributes")
	}
	if err != nil {
		t.Fatal(err)
	}
	requireExecutableRepair(t, root, data, true)
	var got [len(value)]byte
	n, err := syscall.Getxattr(path, attr, got[:])
	if err != nil || n != len(value) || string(got[:]) != value {
		t.Fatalf("repaired file attribute %s = %q (%d bytes, error %v)", attr, got, n, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode() != 0o755 {
		t.Fatalf("repaired mode: %v, %v", info, err)
	}
	requireExecutableRepair(t, root, data, false)
}

// requireExecutableRepair checks whether the live call changed the verified script's mode.
func requireExecutableRepair(t *testing.T, root string, data []byte, wantChange bool) {
	t.Helper()
	changed, err := ReconcileExecutableIn(t.Context(), root, "run", data, false)
	if err != nil || changed != wantChange {
		t.Fatalf("repair = %t, %v, want changed %t", changed, err, wantChange)
	}
}

// TestReconcileExecutableIn_RefusesStaleBytesAndSymlinks checks that neither stale
// observations nor a second path through a symlink can grant execute permission.
func TestReconcileExecutableIn_RefusesStaleBytesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run")
	data := []byte("#!/bin/sh\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, "run", filepath.Join(root, "link"))
	for _, tc := range [...]struct{ name, expected string }{
		{"run", "#!/different\n"},
		{"link", string(data)},
	} {
		for _, dryRun := range [...]bool{true, false} {
			changed, err := ReconcileExecutableIn(t.Context(), root, tc.name, []byte(tc.expected), dryRun)
			if changed || err == nil {
				t.Fatalf("repair %q from %q (dry run %t) = %t, %v", tc.name, tc.expected, dryRun, changed, err)
			}
		}
	}
	requireRepairFile(t, path, data, 0o600)
}

// TestReconcileExecutableIn_RefusesMatchingNonShebang isolates the shebang requirement
// with matching, bounded bytes on a single ordinary inode.
func TestReconcileExecutableIn_RefusesMatchingNonShebang(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run")
	data := []byte("no shebang\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dryRun := range [...]bool{true, false} {
		changed, err := ReconcileExecutableIn(t.Context(), root, "run", data, dryRun)
		if changed || err == nil || !strings.Contains(err.Error(), "shebang") {
			t.Errorf("preview=%t: got changed=%t, err=%v, want shebang refusal", dryRun, changed, err)
		}
		requireRepairFile(t, path, data, 0o600)
	}
}

// TestReconcileExecutableIn_RefusesReplacedParent exchanges two directories with
// identical scripts during a real lock wait, before the validator can inspect the leaf.
func TestReconcileExecutableIn_RefusesReplacedParent(t *testing.T) {
	const checkoutMode os.FileMode = 0o644
	data := []byte("#!/bin/sh\n")
	for _, dryRun := range [...]bool{true, false} {
		t.Run(fmt.Sprintf("preview=%t", dryRun), func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "scripts")
			replacement := filepath.Join(root, "replacement")
			moved := filepath.Join(root, "moved")
			for _, dir := range [...]string{parent, replacement} {
				plantRepairFile(t, dir, data, checkoutMode)
			}
			ctx := replaceParentDuringWait(t, parent, replacement, moved)
			changed, err := ReconcileExecutableIn(ctx, root, filepath.Join("scripts", "run"), data, dryRun)
			if changed || err == nil || !strings.Contains(err.Error(), "parent changed: scripts") {
				t.Errorf("got changed=%t, err=%v, want refusal naming the replaced parent", changed, err)
			}
			requireRepairFile(t, filepath.Join(moved, "run"), data, checkoutMode)
			requireRepairFile(t, filepath.Join(parent, "run"), data, checkoutMode)
		})
	}
}

// replaceParentDuringWait holds the original directory lock until the repair tries to acquire it.
func replaceParentDuringWait(t *testing.T, parent, replacement, moved string) context.Context {
	t.Helper()
	release := holdPlatformLock(t, snapshotDirectory(t, parent))
	pause := lockPause(func(context.Context, time.Duration) bool {
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, parent); err != nil {
			t.Fatal(err)
		}
		release()
		return false
	})
	return context.WithValue(t.Context(), lockPauseKey{}, pause)
}

// plantRepairFile creates an ordinary script with an exact checkout mode despite the process umask.
func plantRepairFile(t *testing.T, dir string, data []byte, mode os.FileMode) {
	t.Helper()
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a fixture directory needs the owner search bit; 0o700 is least privilege
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "run")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// requireRepairFile checks the mode and bytes left at one name after a refusal.
func requireRepairFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != mode || readFileOrEmpty(t, path) != string(data) {
		t.Errorf("expected unchanged bytes and mode %04o at %s: %v, %v", mode, path, info, err)
	}
}
