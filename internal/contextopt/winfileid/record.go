// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

// Package winfileid reads the full identity of an open Windows file.
package winfileid

import "encoding/binary"

// Info is the Windows FILE_ID_INFO layout for the FileIdInfo information class.
type Info struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// Record holds the eight-byte volume serial followed by the sixteen-byte file ID.
type Record [24]byte

// decode reads the little-endian volume serial and all 128 file ID bits.
func (record *Record) decode() Info {
	const serialBytes = 8
	info := Info{VolumeSerialNumber: binary.LittleEndian.Uint64(record[:serialBytes])}
	copy(info.FileID[:], record[serialBytes:])
	return info
}
