//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"errors"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openNativeLeaf acquires a flat leaf relative to a live descriptor. A directory lookup
// refuses other types in the kernel, and a substituted FIFO cannot block either kind.
func openNativeLeaf(parent uintptr, parentName, name string, directory bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	if parent > math.MaxInt {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EBADF}
	}
	fd, err := unix.Openat(int(parent), name, flags, 0)
	if err != nil {
		pathErr := &os.PathError{Op: "openat", Path: name, Err: err}
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.Join(ErrSourceNotRegular, pathErr)
		}
		return nil, pathErr
	}
	if fd < 0 {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EBADF}
	}
	return os.NewFile(uintptr(fd), filepath.Join(parentName, name)), nil
}
