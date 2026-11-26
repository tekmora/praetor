//go:build darwin && !ios

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
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
	if n, err := readDarwinDirents(fd, block[:], statfs); n != 0 || !errors.Is(err, want) {
		t.Fatalf("mount check returned %d bytes, %v; want zero bytes, %v", n, err, want)
	}
}
