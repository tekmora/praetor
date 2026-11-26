//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"os"
	"syscall"
)

// Nonblocking open prevents a concurrent regular-file-to-FIFO replacement from
// hanging before the identity/type check in stableRead. Regular files ignore it.
func openSource(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// openExecutable refuses a symlink at the leaf. Root.OpenFile resolves in-tree
// symlinks, so the caller checks the opened inode against the pinned parent before reading.
func openExecutable(path string) (*os.File, error) {
	// #nosec G304 -- the validated flat leaf must open directly and match the pinned observation.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// singleLink reports whether changing the inode's mode affects only the scaffold name.
func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
