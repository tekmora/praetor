//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openSource opens one leaf of the pinned directory. openat applies O_NOFOLLOW to the
// leaf itself, and O_NONBLOCK prevents a substituted FIFO from blocking the type check.
func openSource(root *os.Root, name string) (*os.File, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return nil, &os.PathError{Op: "openat", Path: name, Err: os.ErrInvalid}
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	// The private parent stays open until openat returns. Its kernel descriptor fits in int.
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0)
	closeErr := parent.Close()
	if err != nil {
		return nil, errors.Join(&os.PathError{Op: "openat", Path: name, Err: err}, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), filepath.Join(root.Name(), name)), nil
}
