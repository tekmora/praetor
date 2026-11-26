//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"math"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DirectoryIdentity is the device and inode of an open directory.
type DirectoryIdentity struct {
	device uint64
	inode  uint64
}

// Identity returns the directory's identity from its retained descriptor.
func (dir *SnapshotDirectory) Identity() (DirectoryIdentity, error) {
	info, err := dir.Stat()
	if err != nil {
		return DirectoryIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return DirectoryIdentity{}, ErrSourceIdentityUnavailable
	}
	// Device numbers are opaque identifiers, including on platforms with a signed dev_t.
	return DirectoryIdentity{uint64(stat.Dev), uint64(stat.Ino)}, nil //#nosec G115 -- preserves all device and inode bits
}

// statListedName inspects one kernel-listed component relative to the retained descriptor.
// AT_SYMLINK_NOFOLLOW classifies links and devices without opening them.
func (dir *SnapshotDirectory) statListedName(ctx context.Context, name string) (os.FileInfo, error) {
	return dir.statUnixListedName(ctx, name, unix.Fstatat)
}

// statUnixListedName keeps the same parent and no-follow flag across interrupted lookups.
func (dir *SnapshotDirectory) statUnixListedName(ctx context.Context, name string,
	fstatat func(int, string, *unix.Stat_t, int) error,
) (os.FileInfo, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	info := &listedUnixInfo{name: name}
	var statErr error
	err = conn.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			statErr = unix.EBADF
			return
		}
		parentFD := int(fd)
		_, statErr = retryInterrupted(ctx, func() (int, error) {
			return 0, fstatat(parentFD, name, &info.stat, unix.AT_SYMLINK_NOFOLLOW)
		})
	})
	if err != nil {
		return nil, err
	}
	if statErr != nil {
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: statErr}
	}
	return info, nil
}

// listedUnixInfo owns the single fstatat observation used for classification and capture.
type listedUnixInfo struct {
	name string
	stat unix.Stat_t
}

// Name returns the enumerated component.
func (i *listedUnixInfo) Name() string { return i.name }

// Size returns the byte count at lookup.
func (i *listedUnixInfo) Size() int64 { return i.stat.Size }

// ModTime returns the modification time at lookup.
func (i *listedUnixInfo) ModTime() time.Time { return time.Unix(i.stat.Mtim.Unix()) }

// IsDir reports whether the observed inode is a directory.
func (i *listedUnixInfo) IsDir() bool { return i.Mode().IsDir() }

// Sys returns the native metadata used for the listing.
func (i *listedUnixInfo) Sys() any { return &i.stat }

// checkIdentity compares the fstatat device and inode to the opened descriptor's stat.
func (listed pinnedListing) checkIdentity(_ *os.File, opened os.FileInfo) error {
	info, ok := listed.FileInfo.(*listedUnixInfo)
	if !ok {
		return checkStatIdentity(listed.FileInfo, opened)
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || info.stat.Dev != stat.Dev || info.stat.Ino != stat.Ino {
		return errSourceChangedWhileOpening
	}
	return nil
}

// unixFileTypes maps the file kind bits returned by fstatat to Go file kinds.
var unixFileTypes = map[uint32]os.FileMode{
	unix.S_IFREG:  0,
	unix.S_IFDIR:  os.ModeDir,
	unix.S_IFLNK:  os.ModeSymlink,
	unix.S_IFCHR:  os.ModeDevice | os.ModeCharDevice,
	unix.S_IFBLK:  os.ModeDevice,
	unix.S_IFIFO:  os.ModeNamedPipe,
	unix.S_IFSOCK: os.ModeSocket,
}

// Mode returns file kind and permission bits, treating an unknown kind as irregular.
func (i *listedUnixInfo) Mode() os.FileMode {
	raw := uint32(i.stat.Mode)
	kind, ok := unixFileTypes[raw&unix.S_IFMT]
	if !ok {
		kind = os.ModeIrregular
	}
	mode := kind | os.FileMode(raw&0o777)
	if raw&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if raw&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if raw&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
