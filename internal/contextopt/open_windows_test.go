//go:build windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"errors"
	"syscall"
	"testing"
)

// TestReadListedSnapshotRefusesReplacementReparsePoint covers Windows reparse-point
// acquisition. Other platforms have no Windows reparse-point open to exercise.
func TestReadListedSnapshotRefusesReplacementReparsePoint(t *testing.T) {
	dir := contextFixture(t, map[string][]byte{"fixture.go": []byte("original")})
	root := snapshotDirectory(t, dir)
	const name = "fixture.go"
	listed, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(name, "original.go"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("original.go", name); err != nil {
		if errors.Is(err, syscall.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("creating a Windows symlink requires Developer Mode or symlink privilege")
		}
		t.Fatal(err)
	}
	data, err := ReadListedSnapshot(t.Context(), root, name, listed)
	if err == nil || data != nil {
		t.Fatalf("replacement link to the listed file returned %d bytes, err %v", len(data), err)
	}
}
