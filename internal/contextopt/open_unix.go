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
func openNativeLeaf(parent uintptr, parentName, name string, access leafAccess) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	if access == listDirectory {
		flags |= unix.O_DIRECTORY
	}
	if parent > math.MaxInt {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EBADF}
	}
	fd, err := unix.Openat(int(parent), name, flags, 0)
	if err != nil {
		pathErr := &os.PathError{Op: "openat", Path: name, Err: err}
		if errors.Is(err, unix.ELOOP) {
			return nil, refusedSourceLink{pathErr}
		}
		return nil, pathErr
	}
	if fd < 0 {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EBADF}
	}
	return os.NewFile(uintptr(fd), filepath.Join(parentName, name)), nil
}

// refusedSourceLink classifies one O_NOFOLLOW failure as a nonregular source.
// The open error is its only cause, so a later close failure remains distinct.
type refusedSourceLink struct{ cause *os.PathError }

// Error names the refused source kind and the failed open.
func (e refusedSourceLink) Error() string {
	return ErrSourceNotRegular.Error() + ": " + e.cause.Error()
}

// Is exposes the source classification to callers inspecting the open failure.
func (e refusedSourceLink) Is(target error) bool { return target == ErrSourceNotRegular }

// Unwrap preserves both the path error and its native errno.
func (e refusedSourceLink) Unwrap() error { return e.cause }
