//go:build windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyWindowsListedRegularReplacement keeps the enumerated violating file alive
// under another name, so the clean replacement necessarily has a distinct identity.
func TestVerifyWindowsListedRegularReplacement(t *testing.T) {
	const name = "listed.go"
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, name, recursiveGo)
	mutated := false
	reader := func(dir string, entries []os.DirEntry) []os.DirEntry {
		if filepath.Base(dir) == bucketNegative {
			mutated = true
			if err := os.Rename(filepath.Join(dir, name), filepath.Join(root, "original.go")); err != nil {
				t.Fatal(err)
			}
			writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, name, cleanGo)
		}
		return entries
	}
	ctx := withBucketReader(t.Context(), reader)
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if !mutated || err == nil || report != nil || !strings.Contains(err.Error(), "source changed while opening") {
		t.Fatalf("replacement after enumeration: mutated=%v report=%+v err=%v", mutated, report, err)
	}
}
