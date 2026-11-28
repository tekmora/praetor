//go:build (linux && !android) || (darwin && !ios) || windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestListedDirectoryKind reuses a native listing record across three relative lookups.
// The stable directory is skippable. Its removal and replacement must retain the name and error.
func TestListedDirectoryKind(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), MaxDuration)
	defer cancel()
	dir, child, path := listedChildDirectory(t, ctx)
	if entry := dir.resolveEntry(ctx, child); entry.Name() != "child" || !entry.IsDir() {
		t.Fatalf("stable directory: %v", entry)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing := dir.resolveEntry(ctx, child)
	if _, err := missing.Info(); missing.Name() != "child" || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing directory: name=%q err=%v", missing.Name(), err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced := dir.resolveEntry(ctx, child)
	if _, err := replaced.Info(); replaced.Name() != "child" || replaced.IsDir() || err == nil {
		t.Errorf("directory replaced by regular file: name=%q err=%v", replaced.Name(), err)
	}
}

// listedChildDirectory returns a pinned cursor and its native observation of a single directory.
func listedChildDirectory(t *testing.T, ctx context.Context) (*SnapshotDirectory, listedName, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "child")
	if err := EnsureDirectory(ctx, path, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := OpenSnapshotDirectoryIn(ctx, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	})
	names, err := dir.readNames(ctx, 1)
	if err != nil || len(names) != 1 {
		t.Fatalf("list child directory: %v, %v", names, err)
	}
	return dir, names[0], path
}
