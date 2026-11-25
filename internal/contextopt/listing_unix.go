//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"math"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// readNames consumes directory records without the per-name stat that can drop an entry.
func (dir *SnapshotDirectory) readNames(n int) ([]listedName, error) {
	names, err := dir.Readdirnames(n)
	listed := make([]listedName, len(names))
	for i, name := range names {
		listed[i].name = name
	}
	return listed, err
}

// statListedName inspects one kernel-listed component relative to the retained descriptor.
// AT_SYMLINK_NOFOLLOW classifies links and devices without opening them.
func (dir *SnapshotDirectory) statListedName(name string) (os.FileInfo, error) {
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
		statErr = unix.Fstatat(int(fd), name, &info.stat, unix.AT_SYMLINK_NOFOLLOW)
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
