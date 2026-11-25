//go:build !windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import "testing"

// TestReadListedSnapshotRefusesReplacementReparsePoint identifies the Windows-only case on other hosts.
func TestReadListedSnapshotRefusesReplacementReparsePoint(t *testing.T) {
	t.Skip("requires the Windows reparse-point open")
}
