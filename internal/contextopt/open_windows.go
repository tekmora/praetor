// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cordanaLLM/praetor/internal/contextopt/winfileid"
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

// readNames keeps enumeration metadata for nonregular entries. Regular entries need a
// descriptor-relative FileIdInfo lookup after all names have been counted.
func (dir *SnapshotDirectory) readNames(n int) ([]listedName, error) {
	infos, readErr := dir.Readdir(n)
	names := make([]listedName, len(infos))
	for i, info := range infos {
		names[i].name = info.Name()
		if !info.Mode().IsRegular() {
			names[i].info = info
		}
	}
	return names, readErr
}

// windowsListedInfo freezes the metadata and full identity from the same listing handle.
type windowsListedInfo struct {
	os.FileInfo
	id winfileid.Info
}

// statListedName captures the regular file's full identity relative to the enumerating parent.
func (dir *SnapshotDirectory) statListedName(name string) (_ os.FileInfo, err error) {
	if err := validateLeafName(name); err != nil {
		return nil, err
	}
	file, err := openLeafAt(dir.File, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return statWindowsFixture(file)
}

// statWindowsFixture freezes size, modification time and FILE_ID_INFO from one handle.
func statWindowsFixture(file *os.File) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("listed regular file %q changed type", file.Name())
	}
	id, err := readFileID(file)
	if err != nil {
		return nil, err
	}
	return windowsListedInfo{info, id}, nil
}

// checkIdentity compares the full listing identity with the handle used to copy the bytes.
func (listed pinnedListing) checkIdentity(file *os.File, _ os.FileInfo) error {
	before, ok := listed.FileInfo.(windowsListedInfo)
	if !ok {
		return ErrSourceIdentityUnavailable
	}
	opened, err := readFileID(file)
	if err != nil {
		return err
	}
	if before.id != opened {
		return errSourceChangedWhileOpening
	}
	return nil
}

// readFileID retains the file handle for the duration of the FileIdInfo query.
func readFileID(file *os.File) (winfileid.Info, error) {
	var id winfileid.Info
	conn, err := file.SyscallConn()
	if err == nil {
		var queryErr error
		err = conn.Control(func(fd uintptr) {
			queryErr = winfileid.Query(windows.Handle(fd), &id)
		})
		err = errors.Join(err, queryErr)
	}
	if err != nil {
		return id, fmt.Errorf("%w: GetFileInformationByHandleEx(FileIdInfo): %w", ErrSourceIdentityUnavailable, err)
	}
	return id, nil
}
