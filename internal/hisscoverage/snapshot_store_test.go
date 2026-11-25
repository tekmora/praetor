// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// TestSnapshotSpillBoundary preserves exactly one MiB in memory and reads the excess
// byte from private storage. A truncated spill must fail and cleanup must remove it.
func TestSnapshotSpillBoundary(t *testing.T) {
	var store fixtureStore
	ctx := t.Context()
	full := bytes.Repeat([]byte{'a'}, 1<<20)
	first, err := store.save(ctx, "first", full)
	if err != nil || len(first.data) != len(full) || store.spill != nil {
		t.Fatalf("exact bound: retained %d bytes, spill %v, err %v", len(first.data), store.spill, err)
	}
	last, err := store.save(ctx, "last", []byte("x"))
	if err != nil || store.spill == nil {
		t.Fatalf("overflow did not spill: %v", err)
	}
	checkSpillRemoved(t, &store)
	checkSpilledByte(t, &store, last)
}

// checkSpilledByte reads the excess byte, then requires a truncated spill to fail.
func checkSpilledByte(t *testing.T, store *fixtureStore, last capturedFixture) {
	t.Helper()
	ctx := t.Context()
	if got, err := store.load(ctx, last); err != nil || string(got) != "x" || cap(last.data) != 0 {
		t.Fatalf("excess byte: got %q, resident capacity %d, err %v", got, cap(last.data), err)
	}
	if err := store.spill.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if data, err := store.load(ctx, last); err == nil || data != nil {
		t.Fatalf("truncated spill yielded %d bytes: %v", len(data), err)
	}
}

// checkSpillRemoved releases the private spill and verifies its path no longer exists.
func checkSpillRemoved(t *testing.T, store *fixtureStore) {
	t.Helper()
	path := store.spill.Name()
	t.Cleanup(func() {
		if err := store.close(); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("spill %q after cleanup: %v", path, err)
		}
	})
}
