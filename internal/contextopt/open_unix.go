//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"

	"github.com/cordanaLLM/praetor/internal/util"
	"golang.org/x/sys/unix"
)

// maxNativeAttempts includes the first call and bounds retries during a signal storm.
const maxNativeAttempts = 8

// retryInterrupted retries isolated EINTR with a zero or -1 result, stopping before
// the next syscall on cancellation. A partial read retains its byte count and error.
func retryInterrupted(ctx context.Context, call func() (int, error)) (int, error) {
	var n int
	var err error
	for range maxNativeAttempts {
		select {
		case <-ctx.Done():
			return n, errors.Join(err, ctx.Err())
		default:
		}
		n, err = call()
		if n < -1 || n > 0 || !errors.Is(util.SoleCause(err), unix.EINTR) {
			return n, err
		}
	}
	if canceled := ctx.Err(); canceled != nil {
		err = errors.Join(err, canceled)
	}
	return n, err
}

// openNativeLeaf acquires a flat leaf relative to a live descriptor. A directory lookup
// refuses other types in the kernel, and a substituted FIFO cannot block either kind.
func openNativeLeaf(ctx context.Context, parent uintptr, parentName, name string, access leafAccess) (*os.File, error) {
	return openUnixLeaf(ctx, parent, parentName, name, access, unix.Openat)
}

// openUnixLeaf keeps the same parent and no-follow flags across interrupted opens.
func openUnixLeaf(ctx context.Context, parent uintptr, parentName, name string, access leafAccess,
	openat func(int, string, int, uint32) (int, error),
) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	if access == listDirectory {
		flags |= unix.O_DIRECTORY
	}
	if parent > math.MaxInt {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EBADF}
	}
	parentFD := int(parent)
	fd, err := retryInterrupted(ctx, func() (int, error) {
		return openat(parentFD, name, flags, 0)
	})
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
