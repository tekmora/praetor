//go:build linux && !android

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// decodeUnknownChild feeds the production decoder a Linux getdents record. Zero is a
// valid inode on Linux. Only the relative metadata lookup can supply the child's kind.
func decodeUnknownChild(t *testing.T, ctx context.Context, dir *SnapshotDirectory) listedName {
	t.Helper()
	record := unknownChildRecord()
	listed, err := dir.decodeDirents(ctx, record[:])
	if err != nil || len(listed) != 1 || listed[0].name != "child" {
		t.Fatalf("decode DT_UNKNOWN: %v, %v", listed, err)
	}
	return listed[0]
}

// unknownChildRecord builds the single native record used by the unknown-kind cases.
func unknownChildRecord() [32]byte {
	var record [32]byte
	// SAFETY: All three compile-time offsets lie within the 32-byte Linux dirent.
	const (
		nameOffset = unsafe.Offsetof(unix.Dirent{}.Name)
		sizeOffset = unsafe.Offsetof(unix.Dirent{}.Reclen)
		typeOffset = unsafe.Offsetof(unix.Dirent{}.Type)
	)
	binary.NativeEndian.PutUint16(record[sizeOffset:], uint16(len(record)))
	record[typeOffset] = unix.DT_UNKNOWN
	copy(record[nameOffset:], "child")
	return record
}

// TestUnknownDirentObservesKind feeds the native decoder the same untyped
// record before and after unlink. Recreating the name cannot repair a failed
// first observation or certify the replacement as the original directory.
func TestUnknownDirentObservesKind(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, _, path := listedChildDirectory(t, ctx)
	before := decodeUnknownChild(t, ctx, dir)
	if entry := dir.resolveEntry(ctx, before); !entry.IsDir() {
		t.Fatalf("stable DT_UNKNOWN directory: %v", entry)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing := decodeUnknownChild(t, ctx, dir)
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := dir.resolveEntry(ctx, missing)
	if _, err := entry.Info(); entry.Name() != "child" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing at first observation: %q, %v", entry.Name(), err)
	}
	entry = dir.resolveEntry(ctx, before)
	if _, err := entry.Info(); entry.Name() != "child" || err == nil || !strings.Contains(err.Error(), "listed kind") {
		t.Fatalf("directory replaced after first observation: %q, %v", entry.Name(), err)
	}
	checkUnknownRegularCapture(t, ctx, dir, path)
}

// checkUnknownRegularCapture changes only the identity between observation and resolution.
func checkUnknownRegularCapture(t *testing.T, ctx context.Context, dir *SnapshotDirectory, path string) {
	t.Helper()
	stable := decodeUnknownChild(t, ctx, dir)
	info := resolvedChildInfo(t, ctx, dir, stable)
	data, err := dir.ReadListedSnapshot(ctx, info.Name(), info)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("stable regular file: %q, %v", data, err)
	}
	if err := os.WriteFile(path+".new", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path+".new", info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	listed := decodeUnknownChild(t, ctx, dir)
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	info = resolvedChildInfo(t, ctx, dir, listed)
	data, err = dir.ReadListedSnapshot(ctx, info.Name(), info)
	var pathErr *os.PathError
	if data != nil || !errors.Is(err, errSourceChangedWhileOpening) ||
		!errors.As(err, &pathErr) || pathErr.Path != "child" {
		t.Fatalf("replaced regular file: data=%q err=%v", data, err)
	}
}

// resolvedChildInfo retrieves the metadata that the listing passes to capture.
func resolvedChildInfo(t *testing.T, ctx context.Context, dir *SnapshotDirectory, listed listedName) os.FileInfo {
	t.Helper()
	info, err := dir.resolveEntry(ctx, listed).Info()
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// TestLastLookupCancellationKeepsBothCauses cancels at the first status check
// after a missing final fstatat, both during resolution and during DT_UNKNOWN decoding.
func TestLastLookupCancellationKeepsBothCauses(t *testing.T) {
	dir, err := OpenSnapshotDirectoryIn(t.Context(), t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	t.Run("final resolution", func(t *testing.T) {
		ctx := cancelAtLookupBoundary(t, 2)
		entries, err := dir.resolveEntries(ctx, []listedName{{name: "child"}})
		if entries != nil || !errors.Is(err, os.ErrNotExist) || !errors.Is(err, context.Canceled) {
			t.Fatalf("final entry: entries=%v err=%v", entries, err)
		}
	})
	t.Run("unknown type", func(t *testing.T) {
		ctx := cancelAtLookupBoundary(t, 3)
		record := unknownChildRecord()
		names, err := CollectDirectoryEntries(ctx, 1, func(int) ([]listedName, error) {
			return dir.decodeDirents(ctx, record[:])
		})
		if names != nil || !errors.Is(err, os.ErrNotExist) || !errors.Is(err, context.Canceled) {
			t.Fatalf("unknown type: names=%v err=%v", names, err)
		}
	})
}

// lookupBoundaryContext counts synchronous status checks on the listing goroutine.
type lookupBoundaryContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

// Err delivers cancellation at the designated listing boundary.
func (c *lookupBoundaryContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

// cancelAtLookupBoundary installs a deadline before the listing starts so each
// native call shares the context used to deliver the boundary cancellation.
func cancelAtLookupBoundary(t *testing.T, checks int) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	t.Cleanup(cancel)
	return &lookupBoundaryContext{Context: ctx, cancel: cancel, remaining: checks}
}
