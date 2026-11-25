//go:build windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
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

// TestWindowsListedDirectoryAttributeAccess classifies a child under a real DACL
// that permits an attribute query while denying a directory-listing handle.
func TestWindowsListedDirectoryAttributeAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, child, path := listedChildDirectory(t, ctx)
	restrictListedDirectory(t, path)
	opened, err := OpenChildDirectory(ctx, dir, child.name)
	if opened != nil {
		if closeErr := opened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("open for listing: %v, want access denied", err)
	}
	entry := dir.resolveEntry(child)
	info, err := entry.Info()
	if err != nil || !info.IsDir() || entry.Name() != child.name {
		t.Fatalf("metadata-only lookup of %q: %v, %v", child.name, info, err)
	}
}

// restrictListedDirectory installs a protected DACL on the empty test directory
// and restores its original access rules before the temporary tree is removed.
func restrictListedDirectory(t *testing.T, path string) {
	t.Helper()
	original, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || original == nil {
		t.Fatalf("get original DACL: %v", err)
	}
	saved, _, err := original.DACL()
	if err != nil {
		t.Fatal(err)
	}
	sddl := fmt.Sprintf("D:P(D;;0x%x;;;WD)(A;;0x%x;;;WD)", windows.FILE_LIST_DIRECTORY, windows.FILE_READ_ATTRIBUTES)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	const set = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, set, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, set, nil, nil, saved, nil); err != nil {
			t.Error(err)
		}
	})
}
