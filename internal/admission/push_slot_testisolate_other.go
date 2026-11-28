// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !unix

package admission

// IsolatePushSlotForTestProcess is a no-op on non-Unix builds where the push slot is refused.
func IsolatePushSlotForTestProcess() (func(), error) {
	return func() {}, nil
}
