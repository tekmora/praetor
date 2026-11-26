//go:build darwin && !ios

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDarwinUnionDirectoryRefusesRead supplies mount flags for a real, unread directory
// descriptor. Each refusal must leave its only child available to the ordinary reader.
func TestDarwinUnionDirectoryRefusesRead(t *testing.T) {
	root := contextFixture(t, map[string][]byte{"child": nil})
	dir, err := OpenSnapshotDirectoryIn(t.Context(), root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	requireDarwinReadRefusal(t, dir.Fd(), nil, ErrUnionDirectory)
	requireDarwinReadRefusal(t, dir.Fd(), unix.EIO, unix.EIO)
	entries, err := dir.ReadEntries(t.Context(), 2)
	if err != nil || len(entries) != 1 || entries[0].Name() != "child" {
		t.Fatalf("cursor after refusal: %v, %v", entries, err)
	}
}

// requireDarwinReadRefusal substitutes the mount reply at the descriptor query boundary.
func requireDarwinReadRefusal(t *testing.T, fd uintptr, statErr, want error) {
	t.Helper()
	var block [direntBlockSize]byte
	statfs := func(got int, stat *unix.Statfs_t) error {
		if got < 0 || uintptr(got) != fd {
			t.Fatalf("fstatfs descriptor %d, want %d", got, fd)
		}
		stat.Flags = unix.MNT_UNION | unix.MNT_RDONLY
		return statErr
	}
	if n, err := readDarwinDirents(t.Context(), fd, block[:], statfs); n != 0 || !errors.Is(err, want) {
		t.Fatalf("mount check returned %d bytes, %v; want zero bytes, %v", n, err, want)
	}
}

// TestDarwinLateMountCheckKeepsCursor cancels during a successful mount query.
// The first directory entry must still be on the same cursor after the refusal.
func TestDarwinLateMountCheckKeepsCursor(t *testing.T) {
	dir, err := OpenSnapshotDirectoryIn(t.Context(), contextFixture(t, map[string][]byte{"first": nil}), ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	var block [direntBlockSize]byte
	count, err := readDarwinDirents(ctx, dir.Fd(), block[:], func(int, *unix.Statfs_t) error {
		cancel()
		return nil
	})
	if count != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("late mount query advanced by %d bytes: %v", count, err)
	}
	entries, err := dir.ReadEntries(t.Context(), 1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "first" {
		t.Fatalf("cursor after canceled mount query: entries=%v err=%v", entries, err)
	}
}
