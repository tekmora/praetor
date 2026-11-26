//go:build !(linux && !android) && !(darwin && !ios) && !windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
)

// readNames refuses enumeration when this build has no verified directory reader.
func (dir *SnapshotDirectory) readNames(_ context.Context, _ int) ([]listedName, error) {
	return nil, errors.ErrUnsupported
}
