package contextopt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Positive: ReplaceSnapshotIn creates an absent file below absent directories when the caller
// observed it absent, and replaces it when the caller's snapshot still matches.
func TestReplaceSnapshotIn_Positive_CreatesAndReplacesBoundSnapshot(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join(".claude", "settings.json")
	if err := ReplaceSnapshotIn(t.Context(), root, rel, []byte("{}\n"), ReplaceOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	options := ReplaceOptions{Expected: []byte("{}\n"), Exists: true, Mode: 0o644}
	if err := ReplaceSnapshotIn(t.Context(), root, rel, []byte("{\"a\": 1}\n"), options); err != nil {
		t.Fatal(err)
	}
	if got := readFileOrEmpty(t, filepath.Join(root, rel)); got != "{\"a\": 1}\n" {
		t.Fatalf("got %q", got)
	}
}

// TestReplaceSnapshotIn_RefusesMatchingCreateByDefault binds an absence observation even
// when the existing file already holds the requested bytes at the requested mode.
func TestReplaceSnapshotIn_RefusesMatchingCreateByDefault(t *testing.T) {
	root := t.TempDir()
	const name = "settings.json"
	path := filepath.Join(root, name)
	content := []byte("{}\n")
	options := ReplaceOptions{Mode: 0o600}
	if err := ReplaceSnapshotIn(t.Context(), root, name, content, options); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	err = ReplaceSnapshotIn(t.Context(), root, name, content, options)
	if !errors.Is(err, errSnapshotExists) || !strings.Contains(err.Error(), name) {
		t.Errorf("default create over an identical file: got %v, want %v naming %s", err, errSnapshotExists, name)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || readFileOrEmpty(t, path) != string(content) {
		t.Error("refused create replaced or changed the existing file")
	}
}

// Negative: a file that changed since the caller's snapshot, a file that appeared although
// the caller observed it absent, and a symlinked file are each refused and left untouched.
func TestReplaceSnapshotIn_Negative_RefusesStaleSnapshotsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	rel := "settings.json"
	path := filepath.Join(root, rel)
	if err := os.WriteFile(path, []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := ReplaceOptions{Expected: []byte("planned\n"), Exists: true, Mode: 0o644}
	if err := ReplaceSnapshotIn(t.Context(), root, rel, []byte("new\n"), stale); err == nil {
		t.Error("stale snapshot accepted")
	}
	if err := ReplaceSnapshotIn(t.Context(), root, rel, []byte("new\n"), ReplaceOptions{Mode: 0o644}); err == nil {
		t.Error("absent snapshot replaced an existing file")
	}
	if got := readFileOrEmpty(t, path); got != "edited\n" {
		t.Fatalf("refused publish changed the file: %q", got)
	}
	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, victim, filepath.Join(root, "linked.json"))
	linked := ReplaceOptions{Expected: []byte("victim\n"), Exists: true, Mode: 0o644}
	if err := ReplaceSnapshotIn(t.Context(), root, "linked.json", []byte("new\n"), linked); err == nil {
		t.Error("symlinked file written through")
	}
	if got := readFileOrEmpty(t, victim); got != "victim\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

// Boundary: an existing empty file is a snapshot of its own, distinct from absence: it is
// replaced when observed as existing and empty, and refused when the caller observed absence.
func TestReplaceSnapshotIn_Boundary_EmptyFileIsNotAbsence(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "hooks.json")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceSnapshotIn(t.Context(), root, "hooks.json", []byte("{}\n"), ReplaceOptions{Mode: 0o644}); err == nil {
		t.Error("absent snapshot replaced an empty file")
	}
	options := ReplaceOptions{Expected: []byte{}, Exists: true, Mode: 0o644}
	if err := ReplaceSnapshotIn(t.Context(), root, "hooks.json", []byte("{}\n"), options); err != nil {
		t.Fatal(err)
	}
	if got := readFileOrEmpty(t, path); got != "{}\n" {
		t.Fatalf("got %q", got)
	}
}
