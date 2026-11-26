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
	listed, err := dir.decodeDirents(ctx, record[:])
	if err != nil || len(listed) != 1 || listed[0].name != "child" {
		t.Fatalf("decode DT_UNKNOWN: %v, %v", listed, err)
	}
	return listed[0]
}

// TestUnknownDirentObservesKind feeds the native decoder the same untyped
// record before and after unlink. Recreating the name cannot repair a failed
// first observation or certify the replacement as the original directory.
func TestUnknownDirentObservesKind(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, _, path := listedChildDirectory(t, ctx)
	before := decodeUnknownChild(t, ctx, dir)
	if entry := dir.resolveEntry(before); !entry.IsDir() {
		t.Fatalf("stable DT_UNKNOWN directory: %v", entry)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing := decodeUnknownChild(t, ctx, dir)
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := dir.resolveEntry(missing)
	if _, err := entry.Info(); entry.Name() != "child" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing at first observation: %q, %v", entry.Name(), err)
	}
	entry = dir.resolveEntry(before)
	if _, err := entry.Info(); entry.Name() != "child" || err == nil || !strings.Contains(err.Error(), "listed kind") {
		t.Fatalf("directory replaced after first observation: %q, %v", entry.Name(), err)
	}
}
