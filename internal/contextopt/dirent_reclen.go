//go:build darwin || freebsd || linux || netbsd || openbsd

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

// direntRecordSize reads d_reclen from the native header preceding d_name.
func direntRecordSize(record []byte) int {
	// SAFETY: This compile-time offset precedes d_name in the checked native header.
	return int(binary.NativeEndian.Uint16(record[unsafe.Offsetof(unix.Dirent{}.Reclen):]))
}
