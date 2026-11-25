//go:build windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReadListedSnapshotRefusesReplacementReparsePoint covers Windows reparse-point
// acquisition. Other platforms have no Windows reparse-point open to exercise.
func TestReadListedSnapshotRefusesReplacementReparsePoint(t *testing.T) {
	dir := contextFixture(t, map[string][]byte{"fixture.go": []byte("original")})
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	root, err := OpenSnapshotDirectoryIn(ctx, dir, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	const name = "fixture.go"
	listed := listedWindowsFixture(t, ctx, root, name)
	data, err := root.ReadListedSnapshot(ctx, name, listed)
	if err != nil || string(data) != "original" {
		t.Fatalf("capture original fixture: %q, %v", data, err)
	}
	if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, "original.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("original.go", filepath.Join(dir, name)); err != nil {
		if errors.Is(err, syscall.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("creating a Windows symlink requires Developer Mode or symlink privilege")
		}
		t.Fatal(err)
	}
	data, err = root.ReadListedSnapshot(ctx, name, listed)
	if err == nil || data != nil {
		t.Fatalf("replacement link to the listed file returned %d bytes, err %v", len(data), err)
	}
}

// listedWindowsFixture gets the original file's full identity from the production listing.
func listedWindowsFixture(t *testing.T, ctx context.Context, root *SnapshotDirectory, name string) os.FileInfo {
	t.Helper()
	entries, err := root.ReadEntries(ctx, 2)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("list original fixture: %v, %v", entries, err)
	}
	listed, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	return listed
}
