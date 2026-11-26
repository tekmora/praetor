//go:build darwin && !ios

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"syscall"
	"unsafe"

	"github.com/cordanaLLM/praetor/internal/util"
	"golang.org/x/sys/unix"
)

// readNativeDirents calls getdirentries64 on the held descriptor. The x/sys ReadDirent
// emulation opens "." and skips records from the start on every call.
func readNativeDirents(ctx context.Context, fd uintptr, buf []byte) (int, error) {
	return readDarwinDirents(ctx, fd, buf, unix.Fstatfs)
}

// readDarwinDirents refuses a union cursor before getdirentries64 can switch its descriptor
// to the lower directory. x/sys/unix v0.50.0 exposes f_flags as Statfs_t.Flags.
func readDarwinDirents(ctx context.Context, fd uintptr, buf []byte, statfs func(int, *unix.Statfs_t) error) (int, error) {
	if fd > math.MaxInt {
		return 0, unix.EBADF
	}
	descriptor := int(fd)
	var mount unix.Statfs_t
	_, err := util.CheckedIO(ctx, func() (int, error) { return 0, statfs(descriptor, &mount) })
	if err != nil {
		return 0, os.NewSyscallError("fstatfs", err)
	}
	if mount.Flags&unix.MNT_UNION != 0 {
		return 0, ErrUnionDirectory
	}
	return util.CheckedIO(ctx, func() (int, error) {
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
	})
}

// direntNameFits checks d_namlen against the payload of a live Darwin record.
func direntNameFits(record []byte) bool {
	if binary.NativeEndian.Uint64(record) == 0 {
		return true
	}
	// SAFETY: This compile-time offset precedes d_name in the checked native header.
	const off = unsafe.Offsetof(unix.Dirent{}.Namlen)
	return int(binary.NativeEndian.Uint16(record[off:])) <= len(record)-direntNameOffset
}
