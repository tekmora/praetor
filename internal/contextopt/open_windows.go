// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"os"
	"syscall"
)

// openSource opens the leaf reparse point itself so the opened-handle regular-file check
// can refuse a replacement link without opening its target.
func openSource(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}
