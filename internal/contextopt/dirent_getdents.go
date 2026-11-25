//go:build dragonfly || freebsd || linux || netbsd || openbsd

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"math"

	"golang.org/x/sys/unix"
)

// readNativeDirents advances the existing descriptor by one native directory block.
func readNativeDirents(fd uintptr, buf []byte) (int, error) {
	if fd > math.MaxInt {
		return 0, unix.EBADF
	}
	return unix.ReadDirent(int(fd), buf)
}
