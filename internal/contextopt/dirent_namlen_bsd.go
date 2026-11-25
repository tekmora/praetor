//go:build darwin || freebsd || netbsd || openbsd

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

// direntNameFits checks d_namlen only for live records. In x/sys v0.50.0 the
// first field on these four systems is the 64-bit Ino (Darwin) or Fileno (BSD).
func direntNameFits(record []byte) bool {
	if binary.NativeEndian.Uint64(record) == 0 {
		return true
	}
	// SAFETY: Both constants describe d_namlen in the already bounded native header.
	const (
		off   = unsafe.Offsetof(unix.Dirent{}.Namlen)
		width = unsafe.Sizeof(unix.Dirent{}.Namlen)
	)
	available := len(record) - direntNameOffset
	if width == 1 {
		return int(record[off]) <= available
	}
	return int(binary.NativeEndian.Uint16(record[off:])) <= available
}
