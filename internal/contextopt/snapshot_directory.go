// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// SnapshotDirectory retains the verified directory descriptor as the root for flat leaf
// opens and as the cursor for its listing. Name is for diagnostics only.
type SnapshotDirectory struct {
	*os.File
}

// OpenSnapshotDirectoryIn acquires every component of rel through its pinned parent.
// The caller owns the returned descriptor.
func OpenSnapshotDirectoryIn(ctx context.Context, root, rel string) (*SnapshotDirectory, error) {
	parts, err := relativeComponents(rel)
	if err != nil {
		return nil, err
	}
	base, err := OpenDirectory(ctx, root)
	if err != nil {
		return nil, err
	}
	current, err := base.Open(".")
	err = errors.Join(err, base.Close())
	if err != nil {
		if current != nil {
			err = errors.Join(err, current.Close())
		}
		return nil, err
	}
	return walkComponents(ctx, &SnapshotDirectory{current}, parts, OpenChildDirectory)
}

// OpenChildDirectory observes the child's identity and acquires the directory without following
// its name through a link. Only absence at the initial observation means a missing bucket.
func OpenChildDirectory(ctx context.Context, dir *SnapshotDirectory, name string) (*SnapshotDirectory, error) {
	if err := validateSnapshotLeaf(ctx, dir, name); err != nil {
		return nil, err
	}
	listed, err := observeLeaf(dir.File, name, true)
	if err != nil {
		return nil, err
	}
	return dir.openListedDirectory(ctx, name, listed)
}

// observeLeaf gets descriptor-backed identity, including on Windows volumes that
// would otherwise defer the file ID lookup until SameFile is called.
func observeLeaf(parent *os.File, name string, directory bool) (_ os.FileInfo, err error) {
	file, err := openLeafAt(parent, name, directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return file.Stat()
}

// openListedDirectory retains the exact handle it checks, so a rename after Stat cannot
// redirect any descendant open. A disappearance after observation is a changed directory.
func (dir *SnapshotDirectory) openListedDirectory(ctx context.Context, name string, listed os.FileInfo) (*SnapshotDirectory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !listed.IsDir() {
		return nil, fmt.Errorf("fixture component %q must be a directory", name)
	}
	child, err := openLeafAt(dir.File, name, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("directory %q disappeared after observation", name)
	}
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat()
	if err == nil && (!opened.IsDir() || !os.SameFile(listed, opened)) {
		err = fmt.Errorf("directory %q changed while opening", name)
	}
	if err != nil {
		return nil, errors.Join(err, child.Close())
	}
	return &SnapshotDirectory{child}, nil
}

// validateSnapshotLeaf confines native relative opens to one ordinary path component.
func validateSnapshotLeaf(ctx context.Context, dir *SnapshotDirectory, name string) error {
	if ctx == nil || dir == nil || dir.File == nil {
		return os.ErrInvalid
	}
	return errors.Join(ctx.Err(), validateLeafName(name))
}

// ReadEntries reads one bounded chunk on the pinned cursor. Unix Readdir obtains
// metadata with fstatat. Windows listings may load file IDs by path on some volumes,
// so Info for a Windows entry instead obtains its ID relative to this live handle.
func (dir *SnapshotDirectory) ReadEntries(ctx context.Context, n int) ([]os.DirEntry, error) {
	if n <= 0 {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	infos, err := dir.Readdir(n)
	entries := make([]os.DirEntry, len(infos))
	for i := range infos {
		entry := fs.FileInfoToDirEntry(infos[i])
		if runtime.GOOS == "windows" {
			entry = handleStatEntry{entry, dir}
		}
		entries[i] = entry
	}
	return entries, err
}

// handleStatEntry loads Windows identity from the open parent, including on volumes
// where the listing carries only a name and attributes.
type handleStatEntry struct {
	os.DirEntry
	dir *SnapshotDirectory
}

// Info observes the current flat leaf without following a reparse point.
func (e handleStatEntry) Info() (os.FileInfo, error) {
	if err := validateLeafName(e.Name()); err != nil {
		return nil, err
	}
	return observeLeaf(e.dir.File, e.Name(), false)
}

// ReadListedSnapshot captures text using the file identity saved by the directory listing.
func (dir *SnapshotDirectory) ReadListedSnapshot(ctx context.Context, name string, listed os.FileInfo) ([]byte, error) {
	if err := validateSnapshotLeaf(ctx, dir, name); err != nil {
		return nil, err
	}
	return readListedText(ctx, listed, func() (*os.File, error) {
		return openLeafAt(dir.File, name, false)
	})
}

// openLeafAt holds a reference to the parent's descriptor until the native open returns,
// including if another caller closes the directory concurrently.
func openLeafAt(parent *os.File, name string, directory bool) (*os.File, error) {
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var child *os.File
	var openErr error
	if err := conn.Control(func(fd uintptr) {
		child, openErr = openNativeLeaf(fd, parent.Name(), name, directory)
	}); err != nil {
		return nil, err
	}
	return child, openErr
}
