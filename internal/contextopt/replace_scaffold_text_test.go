// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReplaceScaffoldTextIn_Positive refreshes observed text without widening its permissions.
func TestReplaceScaffoldTextIn_Positive(t *testing.T) {
	root := t.TempDir()
	if err := ReplaceScaffoldTextIn(t.Context(), root, "template", []byte("v1"), ReplaceOptions{Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	opts := ReplaceOptions{Expected: []byte("v1"), Exists: true, Mode: 0o644}
	if err := ReplaceScaffoldTextIn(t.Context(), root, "template", []byte("revision 2"), opts); err != nil {
		t.Fatal(err)
	}
	assertScaffoldSnapshot(t, filepath.Join(root, "template"), "revision 2", 0o600)
}

// TestReplaceScaffoldTextIn_Negative rejects executable modes and conflicting edits.
func TestReplaceScaffoldTextIn_Negative(t *testing.T) {
	root := t.TempDir()
	if err := ReplaceScaffoldTextIn(t.Context(), root, "template", nil, ReplaceOptions{Mode: 0o755}); err == nil {
		t.Fatal("accepted executable text scaffold")
	}
	opts := ReplaceOptions{Mode: 0o644}
	if err := ReplaceScaffoldTextIn(t.Context(), root, "template", []byte("local"), opts); err != nil {
		t.Fatal(err)
	}
	opts.Exists, opts.Expected = true, []byte("prior")
	if err := ReplaceScaffoldTextIn(t.Context(), root, "template", []byte("updated"), opts); err == nil {
		t.Fatal("accepted a stale refresh over different text")
	}
	assertScaffoldSnapshot(t, filepath.Join(root, "template"), "local", opts.Mode)
}

// TestReplaceScaffoldTextIn_Boundary replays both an empty creation and a stale refresh whose
// desired text exceeds the prior snapshot's read limit.
func TestReplaceScaffoldTextIn_Boundary(t *testing.T) {
	root := t.TempDir()
	opts := ReplaceOptions{Mode: 0o644, ExpectedLimit: 1}
	for range 2 {
		if err := ReplaceScaffoldTextIn(t.Context(), root, "template", nil, opts); err != nil {
			t.Fatal(err)
		}
	}
	opts.Exists = true
	for range 2 {
		if err := ReplaceScaffoldTextIn(t.Context(), root, "template", []byte("longer"), opts); err != nil {
			t.Fatal(err)
		}
	}
	assertScaffoldSnapshot(t, filepath.Join(root, "template"), "longer", opts.Mode)
}

// TestStaleTextRefreshRejectsWiderWinner pins the permission half of the
// matching-publication check even when the stale request already has its desired bytes.
func TestStaleTextRefreshRejectsWiderWinner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot distinguish 0600 and 0644 by mode")
	}
	root := t.TempDir()
	winner := []byte("already published\n")
	if err := ReplaceScaffoldIn(t.Context(), root, "template", winner, ReplaceOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	opts := ReplaceOptions{Exists: true, Expected: []byte("prior\n"), Mode: 0o600}
	err := ReplaceScaffoldTextIn(t.Context(), root, "template", winner, opts)
	if err == nil || !strings.Contains(err.Error(), "snapshot changed") {
		t.Fatalf("stale private refresh returned %v, want snapshot conflict", err)
	}
	assertScaffoldSnapshot(t, filepath.Join(root, "template"), string(winner), 0o644)
}

// stagedSnapshotContext runs a fixture hook at the first context check after
// the private staging entry appears, before final verification reads the destination.
type stagedSnapshotContext struct {
	context.Context
	root    *os.Root
	hook    func(string) error
	changed bool
}

// Err runs the staging hook once and propagates cancellation to the publisher.
func (c *stagedSnapshotContext) Err() error {
	if err := c.Context.Err(); err != nil || c.changed {
		return err
	}
	names, err := fs.Glob(c.root.FS(), ".praetor-*.pending")
	if err != nil || len(names) == 0 {
		return err
	}
	c.changed = true
	return c.hook(names[0])
}

// TestStagedTextPermissionCeiling checks both observations of a text file and the
// independent exact mode for a bundle, with the same deterministic staging hook.
func TestStagedTextPermissionCeiling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot distinguish 0600 and 0644 by mode")
	}
	for _, tc := range [...]struct {
		name                          string
		policy                        snapshotPolicy
		first, final, requested, want os.FileMode
	}{
		{"tightened", scaffoldCeiling, 0o644, 0o600, 0o644, 0o600},
		{"loosened", scaffoldCeiling, 0o600, 0o644, 0o644, 0o600},
		{"bundle", scaffoldExact, 0o644, 0o600, 0o755, 0o755},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := snapshotDirectory(t, dir)
			if err := ReplaceScaffoldTextIn(t.Context(), dir, "template", []byte("prior"), ReplaceOptions{Mode: tc.first}); err != nil {
				t.Fatal(err)
			}
			ctx := &stagedSnapshotContext{Context: t.Context(), root: root, hook: func(string) error {
				return root.Chmod("template", tc.final)
			}}
			opts := ReplaceOptions{Expected: []byte("prior"), Exists: true, Mode: tc.requested}
			if err := replaceInRoot(ctx, root, "template", []byte("updated"), opts, tc.policy); err != nil {
				t.Fatal(err)
			}
			if !ctx.changed {
				t.Fatal("destination mode never changed during staging")
			}
			assertScaffoldSnapshot(t, filepath.Join(dir, "template"), "updated", tc.want)
		})
	}
}
