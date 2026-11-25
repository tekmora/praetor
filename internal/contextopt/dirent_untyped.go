//go:build aix || solaris

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import "context"

// readNames retains every enumerated name on systems whose dirent has no type field.
func (dir *SnapshotDirectory) readNames(ctx context.Context, n int) ([]listedName, error) {
	names, err := dir.Readdirnames(n)
	if err != nil && !IsDirectoryEOF(err) {
		return nil, err
	}
	listed := make([]listedName, len(names))
	for i, name := range names {
		listed[i] = dir.observeUntypedName(ctx, name)
	}
	return listed, err
}
