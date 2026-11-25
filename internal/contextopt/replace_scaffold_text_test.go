// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package contextopt

import (
	"path/filepath"
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
