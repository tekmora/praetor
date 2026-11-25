//go:build !unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"fmt"
	"os"
	"runtime"
)

// openSourceAccess opens the snapshot with the requested access on Windows.
func openSourceAccess(root *os.Root, name string, access int) (*os.File, error) {
	// Windows roots reject reserved devices and cannot address Unix FIFOs. Other
	// platforms lack the required rooted/nonblocking filesystem guarantees.
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("context snapshots require Unix or Windows")
	}
	return root.OpenFile(name, access, 0)
}

// singleLink refuses in-place POSIX mode repairs on hosts without Unix link counts.
func singleLink(os.FileInfo) bool {
	return false
}
