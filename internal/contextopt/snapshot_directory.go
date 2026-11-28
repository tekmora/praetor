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
	"sync"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

// ErrUnionDirectory identifies a Darwin MNT_UNION cursor that can switch directory layers.
var ErrUnionDirectory = errors.New("MNT_UNION can switch the directory descriptor to the lower layer")

// SnapshotDirectory retains the verified directory descriptor as the root for flat leaf
// opens and as the cursor for its listing. Name is for diagnostics only.
type SnapshotDirectory struct {
	*os.File
	listingMu sync.Mutex
	pending   []listedName // Unconsumed records from a native directory read.
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
	current, err := util.CheckedIO(ctx, func() (*os.File, error) { return base.Open(".") })
	err = errors.Join(err, base.Close(), ctx.Err())
	if err != nil {
		if current != nil {
			err = errors.Join(err, current.Close())
		}
		return nil, err
	}
	return walkComponents(ctx, &SnapshotDirectory{File: current}, parts, OpenChildDirectory)
}

// OpenChildDirectory opens a child without following links and retains the handle it
// checks. Listing the directory and opening its descendants use that same handle.
func OpenChildDirectory(ctx context.Context, dir *SnapshotDirectory, name string) (*SnapshotDirectory, error) {
	if err := validateSnapshotLeaf(ctx, dir, name); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	child, err := openLeafAt(ctx, dir.File, name, listDirectory)
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	info, err := statDescriptor(ctx, child)
	if err == nil && !info.IsDir() {
		err = fmt.Errorf("fixture component %q must be a directory", name)
	}
	if err = errors.Join(err, ctx.Err()); err != nil {
		return nil, errors.Join(err, child.Close())
	}
	return &SnapshotDirectory{File: child}, nil
}

// validateSnapshotLeaf confines native relative opens to one ordinary path component.
func validateSnapshotLeaf(ctx context.Context, dir *SnapshotDirectory, name string) error {
	if ctx == nil || dir == nil || dir.File == nil {
		return os.ErrInvalid
	}
	return errors.Join(ctx.Err(), ValidateLeafName(name))
}

// listedName retains the enumerated kind and any metadata obtained to determine it.
type listedName struct {
	name     string
	kind     os.FileMode
	observed os.FileInfo
	err      error
}

// ReadEntries counts up to n names on the pinned cursor before resolving their identities.
// A failed lookup stays in its original slot and its Info method returns the cause.
func (dir *SnapshotDirectory) ReadEntries(ctx context.Context, n int) ([]os.DirEntry, error) {
	if ctx == nil || dir == nil || dir.File == nil {
		return nil, os.ErrInvalid
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > MaxDuration {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, MaxDuration)
		defer cancel()
	}
	dir.listingMu.Lock()
	defer dir.listingMu.Unlock()
	names, err := collectSnapshotNames(ctx, n, func(remaining int) ([]listedName, error) {
		return dir.readNames(ctx, remaining)
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, io.EOF
	}
	return dir.resolveEntries(ctx, names)
}

// collectSnapshotNames retains failed observations if the collector discards a
// chunk on cancellation, including failures returned in an earlier short read.
func collectSnapshotNames(ctx context.Context, n int, next func(int) ([]listedName, error)) ([]listedName, error) {
	var failures []error
	names, err := CollectDirectoryEntries(ctx, n, func(remaining int) ([]listedName, error) {
		chunk, err := next(remaining)
		for _, name := range chunk {
			if name.err != nil {
				failures = append(failures, name.err)
			}
		}
		return chunk, err
	})
	if err != nil && len(failures) != 0 {
		return nil, errors.Join(err, errors.Join(failures...))
	}
	return names, err
}

// resolveEntries checks the descriptor-relative identity of every counted name before returning.
func (dir *SnapshotDirectory) resolveEntries(ctx context.Context, names []listedName) ([]os.DirEntry, error) {
	entries := make([]os.DirEntry, len(names))
	for i, listed := range names {
		if canceled := ctx.Err(); canceled != nil {
			return nil, resolutionError(canceled, entries[:i], names[i:])
		}
		entries[i] = dir.resolveEntry(ctx, listed)
	}
	if canceled := ctx.Err(); canceled != nil {
		return nil, resolutionError(canceled, entries, nil)
	}
	return entries, nil
}

// resolutionError preserves errors from resolved slots and any earlier DT_UNKNOWN
// observations in the remaining slots. It only inspects already frozen metadata.
func resolutionError(canceled error, resolved []os.DirEntry, remaining []listedName) error {
	failures := []error{canceled}
	for _, entry := range resolved {
		if failed, ok := entry.(failedEntry); ok {
			failures = append(failures, failed.err)
		}
	}
	for _, name := range remaining {
		if name.err != nil {
			failures = append(failures, name.err)
		}
	}
	return errors.Join(failures...)
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
func (dir *SnapshotDirectory) resolveEntry(ctx context.Context, listed listedName) os.DirEntry {
	if listed.err != nil {
		return failedEntry{name: listed.name, err: listed.err}
	}
	info, err := dir.statListedName(ctx, listed.name)
	if err != nil {
		return failedEntry{name: listed.name, err: err}
	}
	if current := info.Mode().Type(); listed.kind != current {
		return failedEntry{name: listed.name, err: fmt.Errorf("listed kind %s changed to %s", listed.kind, current)}
	}
	if listed.observed != nil {
		info = listed.observed
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
	file, err := openLeafAt(ctx, dir.File, name, readLeafData)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := stableRead(ctx, file, pinnedListing{listed})
	if err != nil {
		return nil, &os.PathError{Op: "snapshot", Path: name, Err: err}
	}
	if err := validateText(data); err != nil {
		return nil, err
	}
	return data, nil
}

// leafAccess describes the operation to be performed on the returned handle.
type leafAccess uint8

const (
	// readLeafData allows the caller to read fixture bytes.
	readLeafData leafAccess = iota
	// listDirectory allows the caller to enumerate children.
	listDirectory
)

// openLeafAt holds a reference to the parent's descriptor until the native open returns,
// including if another caller closes the directory concurrently.
func openLeafAt(ctx context.Context, parent *os.File, name string, access leafAccess) (*os.File, error) {
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var child *os.File
	var openErr error
	if err := conn.Control(func(fd uintptr) {
		child, openErr = openNativeLeaf(ctx, fd, parent.Name(), name, access)
	}); err != nil {
		if child != nil {
			err = errors.Join(err, child.Close())
		}
		return nil, errors.Join(openErr, err)
	}
	return child, openErr
}
