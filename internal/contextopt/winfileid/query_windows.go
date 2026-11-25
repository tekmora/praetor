// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

// Package winfileid reads the full identity of an open Windows file.
package winfileid

import (
	"encoding/binary"

	"golang.org/x/sys/windows"
)

// Info is the Windows FILE_ID_INFO layout for the FileIdInfo information class.
type Info struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// Query fills info from a live handle. Windows verifier tests substitute the volume response.
var Query = query

// query decodes the fixed-width FILE_ID_INFO returned by the synchronous Windows call.
func query(handle windows.Handle, info *Info) error {
	const serialBytes = 8
	var record [serialBytes + len(info.FileID)]byte
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, &record[0], uint32(len(record))); err != nil {
		return err
	}
	info.VolumeSerialNumber = binary.LittleEndian.Uint64(record[:serialBytes])
	copy(info.FileID[:], record[serialBytes:])
	return nil
}
