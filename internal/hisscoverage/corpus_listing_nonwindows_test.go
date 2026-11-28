//go:build !windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import "testing"

// TestVerifyWindowsListedRegularReplacement identifies the Windows-only identity case.
func TestVerifyWindowsListedRegularReplacement(t *testing.T) {
	t.Skip("requires Windows directory enumeration and volume file-ID handling")
}
