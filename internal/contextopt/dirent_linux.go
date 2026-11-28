//go:build linux && !android

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"math"

	"github.com/cordanaLLM/praetor/internal/util"
	"golang.org/x/sys/unix"
)

// readNativeDirents advances the existing descriptor by one native directory block.
func readNativeDirents(ctx context.Context, fd uintptr, buf []byte) (int, error) {
	if fd > math.MaxInt {
		return 0, unix.EBADF
	}
	descriptor := int(fd)
	return util.CheckedIO(ctx, func() (int, error) { return unix.ReadDirent(descriptor, buf) })
}

// direntNameFits follows from the checked d_reclen, which bounds the Linux name payload.
func direntNameFits(_ []byte) bool { return true }
