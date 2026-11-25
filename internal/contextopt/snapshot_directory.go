// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
	if ctx == nil {
		return nil, os.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	base, err := OpenDirectory(ctx, root)
	if err != nil {
		return nil, err
	}
	current, err := base.Open(".")
	err = errors.Join(err, base.Close(), ctx.Err())
	if err != nil {
		if current != nil {
			err = errors.Join(err, current.Close())
		}
		return nil, err
	}
	return walkComponents(ctx, &SnapshotDirectory{current}, parts, OpenChildDirectory)
}

// OpenChildDirectory opens a child without following links and retains the handle it
// checks. Listing the directory and opening its descendants use that same handle.
func OpenChildDirectory(ctx context.Context, dir *SnapshotDirectory, name string) (*SnapshotDirectory, error) {
	if err := validateSnapshotLeaf(ctx, dir, name); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	child, err := openLeafAt(dir.File, name, true)
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	info, err := child.Stat()
	if err == nil && !info.IsDir() {
		err = fmt.Errorf("fixture component %q must be a directory", name)
	}
	if err = errors.Join(err, ctx.Err()); err != nil {
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

// listedName retains metadata for entries that need no descriptor-relative lookup.
type listedName struct {
	name string
	info os.FileInfo
}

// ReadEntries counts up to n names on the pinned cursor before looking up any leaf.
// A failed lookup stays in its original slot and its Info method returns the cause.
func (dir *SnapshotDirectory) ReadEntries(ctx context.Context, n int) ([]os.DirEntry, error) {
	names, err := CollectDirectoryEntries(ctx, n, dir.readNames)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, io.EOF
	}
	entries := make([]os.DirEntry, len(names))
	for i, listed := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries[i] = dir.resolveEntry(listed)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// CollectDirectoryEntries fills a bounded allowance through short reads. Each successful
// nonterminal read consumes at least one slot. A local directory read can block in the OS.
func CollectDirectoryEntries[T any](ctx context.Context, limit int, next func(int) ([]T, error)) ([]T, error) {
	if ctx == nil || next == nil || limit <= 0 {
		return nil, os.ErrInvalid
	}
	var entries []T
	for reads := 0; reads < limit; reads++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := limit - len(entries)
		chunk, err := next(remaining)
		if canceled := ctx.Err(); canceled != nil {
			return nil, errors.Join(err, canceled)
		}
		if err := checkDirectoryChunk(len(chunk), remaining, err); err != nil {
			return nil, err
		}
		entries = append(entries, chunk...)
		if len(entries) == limit || IsDirectoryEOF(err) {
			return entries, nil
		}
	}
	return nil, io.ErrNoProgress
}

// IsDirectoryEOF recognizes the bare cursor sentinel. A wrapper can carry a read failure.
func IsDirectoryEOF(err error) bool {
	return err == io.EOF //nolint:errorlint // Only the sentinel itself completes a directory listing.
}

// checkDirectoryChunk refuses stalled or oversized responses and propagates read errors.
func checkDirectoryChunk(count, remaining int, err error) error {
	switch {
	case err != nil && !IsDirectoryEOF(err):
		return err
	case count > remaining:
		return fmt.Errorf("directory read returned %d entries for %d slots", count, remaining)
	case count == 0 && err == nil:
		return io.ErrNoProgress
	default:
		return nil
	}
}

// resolveEntry freezes the listed identity before the listing leaves the pinned directory.
func (dir *SnapshotDirectory) resolveEntry(listed listedName) os.DirEntry {
	if listed.info != nil {
		return fs.FileInfoToDirEntry(listed.info)
	}
	info, err := dir.statListedName(listed.name)
	if err != nil {
		return failedEntry{name: listed.name, err: err}
	}
	return fs.FileInfoToDirEntry(info)
}

// failedEntry preserves an enumerated name whose descriptor-relative lookup failed.
type failedEntry struct {
	name string
	err  error
}

// Name returns the original enumerated name.
func (e failedEntry) Name() string { return e.name }

// Type marks the entry as requiring inspection through Info.
func (e failedEntry) Type() os.FileMode { return os.ModeIrregular }

// IsDir cannot certify a directory without metadata.
func (e failedEntry) IsDir() bool { return false }

// Info returns the failure captured at listing time.
func (e failedEntry) Info() (os.FileInfo, error) { return nil, e.err }

// ReadListedSnapshot captures text using the file identity saved by the directory listing.
func (dir *SnapshotDirectory) ReadListedSnapshot(ctx context.Context, name string, listed os.FileInfo) (_ []byte, err error) {
	if err := validateSnapshotLeaf(ctx, dir, name); err != nil {
		return nil, err
	}
	if err := checkListedSource(listed, MaxSourceBytes); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	file, err := openLeafAt(dir.File, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := stableRead(ctx, file, pinnedListing{listed})
	if err != nil {
		return nil, err
	}
	if err := validateText(data); err != nil {
		return nil, err
	}
	return data, nil
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
