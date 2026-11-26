//go:build !unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"fmt"
	"os"
	"runtime"
)

func openSource(root *os.Root, name string) (*os.File, error) {
	// Windows roots reject reserved devices and cannot address Unix FIFOs. Other
	// platforms lack the required rooted/nonblocking filesystem guarantees.
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("context snapshots require Unix or Windows")
	}
	return root.Open(name)
}

// openExecutable refuses a POSIX mode repair on platforms without a no-follow Unix open.
func openExecutable(string) (*os.File, error) {
	return nil, fmt.Errorf("executable mode repair requires POSIX file modes")
}

// singleLink refuses in-place POSIX mode repairs on hosts without Unix link counts.
func singleLink(os.FileInfo) bool {
	return false
}
