// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
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
		{"run", "no shebang\n"},
	} {
		for _, dryRun := range [...]bool{true, false} {
			changed, err := ReconcileExecutableIn(t.Context(), root, tc.name, []byte(tc.expected), dryRun)
			if changed || err == nil {
				t.Fatalf("repair %q from %q (dry run %t) = %t, %v", tc.name, tc.expected, dryRun, changed, err)
			}
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode() != 0o600 || readFileOrEmpty(t, path) != string(data) {
		t.Fatalf("refused repair changed the script: %v, %v", info, err)
	}
}
