//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
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
func (dir *SnapshotDirectory) Identity(ctx context.Context) (DirectoryIdentity, error) {
	info, err := statUnixDescriptor(ctx, dir.File, unix.Fstat)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	return info.identity(), nil
}

// statDescriptor reads a pinned handle without the unbounded EINTR loop in os.File.Stat.
func statDescriptor(ctx context.Context, file *os.File) (os.FileInfo, error) {
	info, err := statUnixDescriptor(ctx, file, unix.Fstat)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// statUnixDescriptor holds the handle while issuing individually checked fstat attempts.
func statUnixDescriptor(ctx context.Context, file *os.File, fstat func(int, *unix.Stat_t) error) (*listedUnixInfo, error) {
	return statUnixFD(ctx, file, file.Name(), "fstat", fstat)
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
	info, err := statUnixFD(ctx, dir.File, name, "fstatat", func(fd int, stat *unix.Stat_t) error {
		return fstatat(fd, name, stat, unix.AT_SYMLINK_NOFOLLOW)
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// statUnixFD keeps the descriptor live across a bounded metadata lookup.
func statUnixFD(ctx context.Context, file *os.File, name, op string, lookup func(int, *unix.Stat_t) error) (*listedUnixInfo, error) {
	conn, err := file.SyscallConn()
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
			return 0, lookup(parentFD, &info.stat)
		})
	})
	if err := errors.Join(err, statErr); err != nil {
		return nil, &os.PathError{Op: op, Path: name, Err: err}
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

// identity treats device and inode numbers as opaque bit patterns.
func (i *listedUnixInfo) identity() DirectoryIdentity {
	return DirectoryIdentity{uint64(i.stat.Dev), uint64(i.stat.Ino)} //#nosec G115 -- preserves all device and inode bits
}

// checkIdentity compares native metadata with either a relative or a standard Go listing.
func (listed pinnedListing) checkIdentity(_ context.Context, _ *os.File, opened os.FileInfo) error {
	current, ok := opened.(*listedUnixInfo)
	if !ok {
		return ErrSourceIdentityUnavailable
	}
	if before, ok := listed.FileInfo.(*listedUnixInfo); ok {
		if before.identity() == current.identity() {
			return nil
		}
		return errSourceChangedWhileOpening
	}
	// SameFile accepts only metadata issued by os. Preserve that requirement
	// before comparing a standard listing to the native descriptor observation.
	if !os.SameFile(listed.FileInfo, listed.FileInfo) {
		return errSourceChangedWhileOpening
	}
	if stat, ok := listed.Sys().(*syscall.Stat_t); ok && stat.Dev == current.stat.Dev && stat.Ino == current.stat.Ino {
		return nil
	}
	return errSourceChangedWhileOpening
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
