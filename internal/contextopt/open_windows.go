// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openNativeLeaf opens the reparse point itself relative to the pinned parent handle.
// Directory type is checked on the handle so a misplaced regular leaf stays distinct
// from a missing bucket, including on Windows filesystems with ambiguous path errors.
func openNativeLeaf(parent uintptr, parentName, name string, _ bool) (*os.File, error) {
	leaf, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(parent),
		ObjectName:    leaf,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	// SAFETY: Sizeof is a compile-time ABI size and dereferences no pointer.
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ, &attrs, &windows.IO_STATUS_BLOCK{},
		nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			err = status.Errno()
		}
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(handle), filepath.Join(parentName, name)), nil
}

// readNames keeps the identity in Go's directory record on volumes that enumerate IDs.
// Other volumes supply names and attributes. Freeze their regular-file IDs from the
// pinned parent after all names are counted, before returning the listing.
func (dir *SnapshotDirectory) readNames(ctx context.Context, n int) ([]listedName, error) {
	infos, readErr := dir.Readdir(n)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(infos) == 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	hasIDs, err := dir.listsFileIDs()
	if err != nil {
		return nil, err
	}
	names := make([]listedName, len(infos))
	for i, info := range infos {
		names[i].name = info.Name()
		if hasIDs || !info.Mode().IsRegular() {
			names[i].info = info
		}
	}
	return names, readErr
}

// listsFileIDs checks the volume flags Go uses to select FILE_ID_BOTH_DIR_INFO.
func (dir *SnapshotDirectory) listsFileIDs() (bool, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return false, err
	}
	var flags uint32
	var volumeErr error
	err = conn.Control(func(fd uintptr) {
		volumeErr = windows.GetVolumeInformationByHandle(windows.Handle(fd), nil, 0, nil, nil, &flags, nil, 0)
	})
	if err != nil {
		return false, err
	}
	// A filesystem without this query also returns name-and-attribute records to Go.
	if errors.Is(volumeErr, windows.ERROR_NOT_SUPPORTED) || errors.Is(volumeErr, windows.ERROR_INVALID_FUNCTION) {
		return false, nil
	}
	const required = windows.FILE_SUPPORTS_OBJECT_IDS | windows.FILE_SUPPORTS_OPEN_BY_FILE_ID
	return flags&required == required, volumeErr
}

// statListedName captures a fallback identity through the enumerating parent.
func (dir *SnapshotDirectory) statListedName(name string) (os.FileInfo, error) {
	if err := validateLeafName(name); err != nil {
		return nil, err
	}
	info, err := observeLeaf(dir.File, name, false)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("listed regular file %q changed type", name)
	}
	return info, nil
}
