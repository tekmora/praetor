//go:build darwin || freebsd || netbsd || openbsd

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bsdTestDirent makes an aligned native record with an optional live inode.
func bsdTestDirent(inode uint64, oversized bool) []byte {
	const recordSize = 64
	var record [recordSize]byte
	// SAFETY: All offsets and widths are compile-time constants in the native record header.
	const (
		nameOffset   = unsafe.Offsetof(unix.Dirent{}.Name)
		lengthOffset = unsafe.Offsetof(unix.Dirent{}.Namlen)
		lengthWidth  = unsafe.Sizeof(unix.Dirent{}.Namlen)
		sizeOffset   = unsafe.Offsetof(unix.Dirent{}.Reclen)
		typeOffset   = unsafe.Offsetof(unix.Dirent{}.Type)
	)
	length := byte(len("child"))
	if oversized {
		length = byte(recordSize - nameOffset + 1)
	}
	if lengthWidth == 1 {
		record[lengthOffset] = length
	} else {
		binary.NativeEndian.PutUint16(record[lengthOffset:], uint16(length))
	}
	binary.NativeEndian.PutUint64(record[:], inode)
	binary.NativeEndian.PutUint16(record[sizeOffset:], recordSize)
	record[typeOffset] = unix.DT_REG
	copy(record[nameOffset:], "child")
	return record[:]
}

// TestBSDDirentNameBounds separates live names, unused slots with stale lengths,
// and an in-bounds record whose declared name extends one byte past its end.
func TestBSDDirentNameBounds(t *testing.T) {
	dir, err := OpenSnapshotDirectoryIn(t.Context(), t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	good := append(bsdTestDirent(0, true), bsdTestDirent(1, false)...)
	names, err := dir.decodeDirents(t.Context(), good)
	if err != nil || len(names) != 1 || names[0].name != "child" {
		t.Fatalf("unused slot followed by a live record: %v, %v", names, err)
	}
	names, err = dir.decodeDirents(t.Context(), append(good, bsdTestDirent(1, true)...))
	if names != nil || err == nil || !strings.Contains(err.Error(), "d_namlen") ||
		!strings.Contains(err.Error(), dir.Name()) {
		t.Fatalf("oversized live name after a valid entry: %v, %v", names, err)
	}
}
