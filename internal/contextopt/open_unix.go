//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"os"
	"syscall"
)

// openSourceAccess uses a nonblocking open to prevent a concurrent regular-file-to-FIFO replacement
// from hanging before the identity/type check in stableRead. Regular files ignore it.
func openSourceAccess(root *os.Root, name string, access int) (*os.File, error) {
	return root.OpenFile(name, access|syscall.O_NONBLOCK, 0)
}

// singleLink reports whether changing the inode's mode affects only the scaffold name.
func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
