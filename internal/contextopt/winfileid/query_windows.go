// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package winfileid

import "golang.org/x/sys/windows"

// ReadRecord reads the raw FileIdInfo response. Tests substitute volume records here
// so listing and capture still use the same decoder as a live volume.
var ReadRecord = readRecord

// readRecord obtains the fixed-width record from the synchronous Windows call.
func readRecord(handle windows.Handle, record *Record) error {
	return windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, &record[0], uint32(len(record)))
}

// Query decodes the complete volume serial and file ID returned for the open handle.
func Query(handle windows.Handle, info *Info) error {
	var record Record
	if err := ReadRecord(handle, &record); err != nil {
		return err
	}
	*info = record.decode()
	return nil
}
