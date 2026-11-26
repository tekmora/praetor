//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// TestResolvedSlotPreservesInterruptedLookup feeds the last slot the result of
// an interrupted relative lookup, as for a DT_UNKNOWN record observed during decode.
func TestResolvedSlotPreservesInterruptedLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, err := OpenSnapshotDirectoryIn(ctx, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, calls, lookupErr := interruptedMetadata(ctx, dir, "last", cancel)
	requireCanceledInterruption(t, calls, lookupErr)
	entries, err := dir.resolveEntries(ctx, []listedName{{name: "last", err: lookupErr}})
	if entries != nil || !errors.Is(err, lookupErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal lookup lost its native error: entries=%v err=%v", entries, err)
	}
}

// TestIdentityFstatAttempts observes the descriptor-query boundary on attempt eight.
// A live interruption exhausts the budget, and a late result retains the deadline.
func TestIdentityFstatAttempts(t *testing.T) {
	dir, err := OpenSnapshotDirectoryIn(t.Context(), t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, expire := range [...]bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
		calls := 0
		last := fmt.Errorf("descriptor query: %w", unix.EINTR)
		info, err := statUnixDescriptor(ctx, dir.File, func(int, *unix.Stat_t) error {
			calls++
			if calls == 8 && expire {
				cancel()
			}
			return last
		})
		cancel()
		if info != nil || calls != 8 || !errors.Is(err, last) || errors.Is(err, context.Canceled) != expire {
			t.Fatalf("identity fstat: expire=%v calls=%d info=%v err=%v", expire, calls, info, err)
		}
	}
}

// TestPinnedCopyAcceptsStandardStat requires an os-issued listing for the
// standard-stat fallback. A wrapper exposing identical Sys data has no such identity.
func TestPinnedCopyAcceptsStandardStat(t *testing.T) {
	const name = "sample"
	root := contextFixture(t, map[string][]byte{name: []byte("listed")})
	dir, err := OpenSnapshotDirectoryIn(t.Context(), root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	info, err := os.Stat(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	data, err := dir.ReadListedSnapshot(t.Context(), name, info)
	if err != nil || string(data) != "listed" {
		t.Fatalf("standard listing: data=%q err=%v", data, err)
	}
	data, err = dir.ReadListedSnapshot(t.Context(), name, struct{ os.FileInfo }{info})
	if data != nil || !errors.Is(err, errSourceChangedWhileOpening) {
		t.Fatalf("wrapped listing: data=%q err=%v", data, err)
	}
}
