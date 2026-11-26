// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cordanaLLM/praetor/internal/contextopt/winfileid"
	"github.com/cordanaLLM/praetor/internal/util"
	"golang.org/x/sys/windows"
)

// readLeafAttributes requests only the attributes needed to classify a listed Windows leaf.
const readLeafAttributes leafAccess = listDirectory + 1

// DirectoryIdentity retains the full volume serial and 128-bit file ID of a directory.
type DirectoryIdentity = winfileid.Info

// Identity queries the directory's retained handle for its full Windows identity.
func (dir *SnapshotDirectory) Identity(ctx context.Context) (DirectoryIdentity, error) {
	return readFileID(ctx, dir.File)
}

// openNativeLeaf opens the reparse point itself relative to the pinned parent handle.
// Directory type is checked on the handle so a misplaced regular leaf stays distinct
// from a missing bucket, including on Windows filesystems with ambiguous path errors.
func openNativeLeaf(ctx context.Context, parent uintptr, parentName, name string, access leafAccess) (*os.File, error) {
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
	rights := uint32(windows.FILE_GENERIC_READ)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if access == readLeafAttributes {
		rights = windows.FILE_READ_ATTRIBUTES
		// A synchronous open would also require SYNCHRONIZE for an attribute query.
		options = windows.FILE_OPEN_REPARSE_POINT
	}
	file, err := util.CheckedIO(ctx, func() (*os.File, error) {
		var handle windows.Handle
		err := windows.NtCreateFile(&handle, rights, &attrs, &windows.IO_STATUS_BLOCK{},
			nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			windows.FILE_OPEN, options, 0, 0)
		if err != nil {
			var status windows.NTStatus
			if errors.As(err, &status) {
				err = status.Errno()
			}
			return nil, err
		}
		return os.NewFile(uintptr(handle), filepath.Join(parentName, name)), nil
	})
	if err != nil {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return file, nil
}

// readNames keeps each Windows directory record's kind for the later relative lookup.
func (dir *SnapshotDirectory) readNames(ctx context.Context, n int) ([]listedName, error) {
	infos, readErr := util.CheckedIO(ctx, func() ([]os.FileInfo, error) { return dir.Readdir(n) })
	names := make([]listedName, len(infos))
	for i, info := range infos {
		names[i] = listedName{name: info.Name(), kind: info.Mode().Type()}
	}
	return names, readErr
}

// windowsListedInfo freezes the metadata and full identity from the same listing handle.
type windowsListedInfo struct {
	os.FileInfo
	id winfileid.Info
}

// statListedName checks the current kind and captures regular file identity relative to the parent.
func (dir *SnapshotDirectory) statListedName(ctx context.Context, name string) (_ os.FileInfo, err error) {
	if err := ValidateLeafName(name); err != nil {
		return nil, err
	}
	file, err := openLeafAt(ctx, dir.File, name, readLeafAttributes)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return statWindowsFixture(ctx, file)
}

// statWindowsFixture obtains the current kind and, for regular files, FILE_ID_INFO on the same handle.
func statWindowsFixture(ctx context.Context, file *os.File) (os.FileInfo, error) {
	info, err := statDescriptor(ctx, file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return info, nil
	}
	id, err := readFileID(ctx, file)
	if err != nil {
		return nil, err
	}
	return windowsListedInfo{info, id}, nil
}

// checkIdentity compares the full listing identity with the handle used to copy the bytes.
func (listed pinnedListing) checkIdentity(ctx context.Context, file *os.File, _ os.FileInfo) error {
	before, ok := listed.FileInfo.(windowsListedInfo)
	if !ok {
		return ErrSourceIdentityUnavailable
	}
	opened, err := readFileID(ctx, file)
	if err != nil {
		return err
	}
	if before.id != opened {
		return errSourceChangedWhileOpening
	}
	return nil
}

// readFileID retains the file handle for the duration of the FileIdInfo query.
func readFileID(ctx context.Context, file *os.File) (winfileid.Info, error) {
	var id winfileid.Info
	conn, err := file.SyscallConn()
	if err == nil {
		var queryErr error
		err = conn.Control(func(fd uintptr) {
			queryErr = winfileid.Query(ctx, windows.Handle(fd), &id)
		})
		err = errors.Join(err, queryErr)
	}
	if err != nil {
		return id, fmt.Errorf("%w: GetFileInformationByHandleEx(FileIdInfo): %w", ErrSourceIdentityUnavailable, err)
	}
	return id, nil
}
