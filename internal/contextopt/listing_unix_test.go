//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestListedMetadataRetriesEINTR uses the second lookup's identity to read the listed file.
func TestListedMetadataRetriesEINTR(t *testing.T) {
	const name = "sample.txt"
	const contents = "listed contents"
	root := contextFixture(t, map[string][]byte{name: []byte(contents)})
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, err := OpenSnapshotDirectoryIn(ctx, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	info, calls, err := interruptedMetadata(ctx, dir, name, func() {})
	if err != nil || calls != 2 || info.Name() != name {
		t.Fatalf("interrupted fstatat: info=%v calls=%d err=%v", info, calls, err)
	}
	data, err := dir.ReadListedSnapshot(ctx, name, info)
	if err != nil || string(data) != contents {
		t.Fatalf("read using retried metadata: data=%q err=%v", data, err)
	}
	t.Run("cancellation", func(t *testing.T) {
		child, stop := context.WithCancel(ctx)
		defer stop()
		info, calls, err := interruptedMetadata(child, dir, name, stop)
		requireCanceledInterruption(t, calls, err)
		if info != nil {
			t.Fatalf("canceled fstatat returned metadata: %v", info)
		}
	})
}

// interruptedMetadata injects one interrupted fstatat, then forwards the real lookup.
func interruptedMetadata(ctx context.Context, dir *SnapshotDirectory, name string, interrupt func()) (os.FileInfo, int, error) {
	calls := 0
	info, err := dir.statUnixListedName(ctx, name, func(fd int, leaf string, stat *unix.Stat_t, flags int) error {
		calls++
		if calls == 1 {
			interrupt()
			return unix.EINTR
		}
		return unix.Fstatat(fd, leaf, stat, flags)
	})
	return info, calls, err
}
