// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

// direntRecordSize rounds the DragonFly header, name and NUL up to the native 8-byte boundary.
func direntRecordSize(record []byte) int {
	// SAFETY: Both offsets are compile-time constants in the checked native header.
	const (
		lengthOffset = unsafe.Offsetof(unix.Dirent{}.Namlen)
		nameOffset   = int(unsafe.Offsetof(unix.Dirent{}.Name))
	)
	size := int(binary.NativeEndian.Uint16(record[lengthOffset:]))
	return (nameOffset + size + 1 + 7) &^ 7
}
