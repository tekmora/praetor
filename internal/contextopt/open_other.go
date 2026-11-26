//go:build !unix && !windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"fmt"
	"os"
)

// openNativeLeaf refuses platforms without the pinned snapshot opener.
func openNativeLeaf(_ uintptr, _, _ string, _ leafAccess) (*os.File, error) {
	return nil, fmt.Errorf("context snapshots require Unix or Windows")
}

// statListedName refuses unpinned leaf metadata.
func (dir *SnapshotDirectory) statListedName(_ string) (os.FileInfo, error) {
	return nil, os.ErrInvalid
}

// checkIdentity refuses unsupported descriptor-relative observations.
func (listed pinnedListing) checkIdentity(_ *os.File, _ os.FileInfo) error {
	return ErrSourceIdentityUnavailable
}
