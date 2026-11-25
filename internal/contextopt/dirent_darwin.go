// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readNativeDirents calls getdirentries64 on the held descriptor. The x/sys ReadDirent
// emulation opens "." and skips records from the start on every call.
func readNativeDirents(fd uintptr, buf []byte) (int, error) {
	var base int64
	// SAFETY: Both pointers refer to live output buffers for this synchronous syscall.
	size, _, errno := syscall.Syscall6(unix.SYS_GETDIRENTRIES64, fd,
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), //#nosec G103 -- kernel writes at most len(buf) bytes during this call
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&base)), 0, 0) //#nosec G103 -- kernel writes one off_t into the live 64-bit local
	if errno != 0 {
		return 0, errno
	}
	if size > uintptr(len(buf)) {
		return 0, unix.EIO
	}
	return int(size), nil
}
