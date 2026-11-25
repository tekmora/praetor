// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReplaceScaffoldIn_KeepsXattr checks a user attribute across a byte-identical mode repair.
func TestReplaceScaffoldIn_KeepsXattr(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run")
	data := []byte("#!/bin/sh\n")
	if err := ReplaceScaffoldIn(t.Context(), root, "run", data, ReplaceOptions{Mode: 0o644}); err != nil {
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
	opts := ReplaceOptions{Expected: data, Exists: true, Mode: 0o755}
	if err := ReplaceScaffoldIn(t.Context(), root, "run", data, opts); err != nil {
		t.Fatal(err)
	}
	var got [len(value)]byte
	n, err := syscall.Getxattr(path, attr, got[:])
	if err != nil || n != len(value) || string(got[:]) != value {
		t.Fatalf("repaired file attribute %s = %q (%d bytes, error %v)", attr, got, n, err)
	}
	assertScaffoldSnapshot(t, path, string(data), opts.Mode)
}
