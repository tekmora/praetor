//go:build !unix && !windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"fmt"
	"os"
)

// openNativeLeaf refuses platforms without the pinned snapshot opener.
func openNativeLeaf(_ uintptr, _, _ string, _ bool) (*os.File, error) {
	return nil, fmt.Errorf("context snapshots require Unix or Windows")
}
