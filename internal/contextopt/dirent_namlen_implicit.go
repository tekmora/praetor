//go:build linux || dragonfly

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

// direntNameFits follows from the checked record size. Linux derives the name
// payload from d_reclen, and DragonFly derives the record size from d_namlen.
func direntNameFits(_ []byte) bool { return true }
