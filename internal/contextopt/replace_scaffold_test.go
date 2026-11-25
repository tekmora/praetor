// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// assertScaffoldSnapshot checks file existence, exact bytes and the platform's mode.
func assertScaffoldSnapshot(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFileOrEmpty(t, path); got != content {
		t.Fatalf("%s contains %q, want %q", path, got, content)
	}
	if runtime.GOOS == "windows" {
		if info.Mode()&0o200 != mode&0o200 {
			t.Errorf("%s has wrong read-only attribute: %v", path, info.Mode())
		}
		return
	}
	if info.Mode() != mode {
		t.Errorf("%s mode = %v, want %v", path, info.Mode(), mode)
	}
}

// TestReplaceScaffoldIn_Positive publishes an executable over the caller's observed text.
func TestReplaceScaffoldIn_Positive(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("hooks", "run")
	if err := ReplaceScaffoldIn(t.Context(), root, rel, []byte("old"), ReplaceOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	options := ReplaceOptions{Expected: []byte("old"), Exists: true, Mode: 0o755}
	if err := ReplaceScaffoldIn(t.Context(), root, rel, []byte("#!new\n"), options); err != nil {
		t.Fatal(err)
	}
	assertScaffoldSnapshot(t, filepath.Join(root, rel), "#!new\n", options.Mode)
}

// TestReplaceScaffoldIn_Negative rejects invalid distribution modes before creating parents.
func TestReplaceScaffoldIn_Negative(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("new", "run")
	for _, mode := range [...]os.FileMode{0, 0o600, 0o645, 0o754, 0o775, os.ModeSetuid | 0o755} {
		if err := ReplaceScaffoldIn(t.Context(), root, rel, nil, ReplaceOptions{Mode: mode}); err == nil {
			t.Errorf("accepted invalid scaffold mode %v", mode)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid request touched parent: %v", err)
	}
}

// TestReplaceScaffoldIn_Boundary replays two creators' identical absence observations on
// an empty file at each accepted mode, then tries the same stale creation with different bytes.
func TestReplaceScaffoldIn_Boundary(t *testing.T) {
	for _, mode := range [...]os.FileMode{0o644, 0o755} {
		root := t.TempDir()
		options := ReplaceOptions{Mode: mode}
		for range 2 {
			if err := ReplaceScaffoldIn(t.Context(), root, "source", nil, options); err != nil {
				t.Fatalf("matching creator at %v: %v", mode, err)
			}
		}
		if err := ReplaceScaffoldIn(t.Context(), root, "source", []byte("other"), options); err == nil {
			t.Error("accepted a concurrent creator's different text")
		}
		assertScaffoldSnapshot(t, filepath.Join(root, "source"), "", mode)
	}
}

// TestReplaceScaffoldIn_ConflictingMode refuses to adopt a concurrent creator's different mode.
func TestReplaceScaffoldIn_ConflictingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX execute bit")
	}
	root := t.TempDir()
	if err := ReplaceScaffoldIn(t.Context(), root, "run", nil, ReplaceOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceScaffoldIn(t.Context(), root, "run", nil, ReplaceOptions{Mode: 0o755}); err == nil {
		t.Fatal("accepted a concurrent creator's different mode")
	}
	assertScaffoldSnapshot(t, filepath.Join(root, "run"), "", 0o644)
}

// TestReplaceScaffoldIn_SharedInode refuses a mode repair that would affect another path.
func TestReplaceScaffoldIn_SharedInode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX execute bit")
	}
	root := t.TempDir()
	path := filepath.Join(root, "source")
	if err := ReplaceScaffoldIn(t.Context(), root, "source", nil, ReplaceOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceScaffoldIn(t.Context(), root, "source", nil, ReplaceOptions{Exists: true, Mode: 0o755}); err == nil {
		t.Fatal("accepted a mode change on a shared inode")
	}
	assertScaffoldSnapshot(t, path, "", 0o644)
	assertScaffoldSnapshot(t, link, "", 0o644)
}

// TestReplaceOptionsLayout pins the names, types and order of the four positional fields.
func TestReplaceOptionsLayout(t *testing.T) {
	type positional struct {
		Expected      []byte
		Exists        bool
		Mode          os.FileMode
		ExpectedLimit int64
	}
	got, want := reflect.TypeFor[ReplaceOptions](), reflect.TypeFor[positional]()
	if !got.ConvertibleTo(want) {
		t.Fatalf("ReplaceOptions must have the same positional fields as %#v", positional{})
	}
}
