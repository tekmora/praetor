//go:build (linux && !android) || (darwin && !ios)

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDirentReadRetriesInterruption accepts the next data after the native read
// reports zero progress, including the -1 count used by getdents on error.
func TestDirentReadRetriesInterruption(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	root := contextFixture(t, map[string][]byte{"child": nil})
	for _, interrupted := range [...]int{0, -1} {
		requireInterruptedBlock(t, ctx, root, interrupted)
	}
}

// requireInterruptedBlock interrupts the first syscall, then returns a real native
// block from the same held descriptor. The block must reach the decoder.
func requireInterruptedBlock(t *testing.T, ctx context.Context, root string, interrupted int) {
	t.Helper()
	dir, err := OpenSnapshotDirectoryIn(ctx, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	calls := 0
	read := func(fd uintptr, buf []byte) (int, error) {
		calls++
		if calls == 1 {
			return interrupted, unix.EINTR
		}
		return readNativeDirents(ctx, fd, buf)
	}
	names, err := dir.readDirentBlock(ctx, read)
	if err != nil || calls != 2 {
		t.Fatalf("read after EINTR: entries=%v calls=%d err=%v", names, calls, err)
	}
}

// TestDirentReadStopsAtBound retains the exact final interruption on exhaustion.
func TestDirentReadStopsAtBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	calls := 0
	var last error
	n, err := retryInterrupted(ctx, func() (int, error) {
		calls++
		last = fmt.Errorf("attempt %d: %w", calls, unix.EINTR)
		return 0, last
	})
	if n != 0 || calls != 8 || !errors.Is(err, last) {
		t.Fatalf("exhausted read: n=%d calls=%d err=%v, want %v", n, calls, err, last)
	}
}

// TestDirentReadPreservesTerminalErrors prevents retries after partial progress,
// a compound failure, or cancellation delivered with the interruption.
func TestDirentReadPreservesTerminalErrors(t *testing.T) {
	for _, tc := range [...]struct {
		n      int
		err    error
		cancel bool
	}{
		{-2, unix.EINTR, false},
		{1, unix.EINTR, false},
		{0, errors.Join(unix.EINTR, unix.EIO), false},
		{0, unix.EINTR, true},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
		calls := 0
		n, err := retryInterrupted(ctx, func() (int, error) {
			calls++
			if tc.cancel {
				cancel()
			}
			return tc.n, tc.err
		})
		cancel()
		if calls != 1 || n != tc.n || !errors.Is(err, tc.err) || errors.Is(err, context.Canceled) != tc.cancel {
			t.Fatalf("interrupted read: n=%d err=%v calls=%d, case %+v", n, err, calls, tc)
		}
	}
}

// TestCanceledNameCollectionRetainsSlots cancels at the second cursor return,
// after both observations have already been stored in their respective chunks.
func TestCanceledNameCollectionRetainsSlots(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	first := fmt.Errorf("first observation: %w", unix.EINTR)
	last := fmt.Errorf("last observation: %w", unix.EIO)
	calls := 0
	names, err := collectSnapshotNames(ctx, 2, func(int) ([]listedName, error) {
		calls++
		if calls == 1 {
			return []listedName{{name: "first", err: first}}, nil
		}
		cancel()
		return []listedName{{name: "last", err: last}}, nil
	})
	if names != nil || calls != 2 || !errors.Is(err, context.Canceled) || !errors.Is(err, first) || !errors.Is(err, last) {
		t.Fatalf("canceled short reads: names=%v calls=%d err=%v", names, calls, err)
	}
}
