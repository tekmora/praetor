// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !unix

package admission

import "testing"

// PushSlotTestBase skips t on non-Unix builds: the host push slot is a Unix lock and WaitPushSlot refuses there
// (push_slot_other_test.go covers that refusal), so a test that takes the slot has nothing to run.
func PushSlotTestBase(t *testing.T) string {
	t.Helper()
	t.Skip("push slot is Unix-only; WaitPushSlot refuses on this platform")
	return ""
}
