//go:build windows

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt/winfileid"
	"golang.org/x/sys/windows"
)

// TestVerifyWindowsListedRegularReplacement checks a physical replacement and volume
// responses that a CI filesystem cannot allocate on demand.
func TestVerifyWindowsListedRegularReplacement(t *testing.T) {
	t.Run("physical replacement", verifyPhysicalWindowsReplacement)
	for _, outcome := range [...]string{"same file", "high ID changed", "volume changed", "listing unsupported", "open unsupported"} {
		t.Run(outcome, func(t *testing.T) { verifyWindowsFileID(t, outcome) })
	}
}

// verifyPhysicalWindowsReplacement keeps the enumerated violating file alive
// under another name, so a replacement with the same bytes and timestamp has a distinct physical identity.
func verifyPhysicalWindowsReplacement(t *testing.T) {
	t.Helper()
	const name = "listed.go"
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, name, recursiveGo)
	mutated := false
	reader := func(dir string, entries []os.DirEntry) []os.DirEntry {
		if filepath.Base(dir) == bucketNegative {
			mutated = true
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, filepath.Join(root, "original.go")); err != nil {
				t.Fatal(err)
			}
			writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, name, recursiveGo)
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}
		return entries
	}
	ctx := withBucketReader(t.Context(), reader)
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	if !mutated || err == nil || report != nil || !strings.Contains(err.Error(), "source changed while opening") {
		t.Fatalf("replacement after enumeration: mutated=%v report=%+v err=%v", mutated, report, err)
	}
}

// verifyWindowsFileID changes the volume response at the real listing boundary. Keeping
// the physical file in place gives both observations the same legacy index, size and mtime.
func verifyWindowsFileID(t *testing.T, outcome string) {
	t.Helper()
	const name = "listed.go"
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, name, recursiveGo)
	listed := false
	var reads [2]int
	query := winfileid.Query
	t.Cleanup(func() { winfileid.Query = query })
	winfileid.Query = func(handle windows.Handle, id *winfileid.Info) error {
		if listed {
			reads[1]++
		} else {
			reads[0]++
		}
		if err := query(handle, id); err != nil {
			return err
		}
		return modelVolumeResponse(outcome, listed, id)
	}
	ctx := withBucketReader(t.Context(), func(dir string, entries []os.DirEntry) []os.DirEntry {
		if filepath.Base(dir) == bucketPositive {
			listed = true
		}
		return entries
	})
	report, err := Verify(ctx, root, catalogFor("HISS-01", "go", StateEnforced))
	checkWindowsFileIDOutcome(t, outcome, name, report, err)
	want := [2]int{1, 1}
	if outcome == "listing unsupported" {
		want[1] = 0
	}
	if !listed || reads != want {
		t.Fatalf("listing hook=%v, FileIdInfo reads [listing open]=%v, want %v", listed, reads, want)
	}
}

// modelVolumeResponse changes only the selected portion of the native query result.
func modelVolumeResponse(outcome string, listed bool, id *winfileid.Info) error {
	switch {
	case !listed && outcome == "listing unsupported", listed && outcome == "open unsupported":
		return windows.ERROR_NOT_SUPPORTED
	case listed && outcome == "high ID changed":
		id.FileID[15] ^= 0x80
	case listed && outcome == "volume changed":
		id.VolumeSerialNumber ^= 1 << 63
	}
	return nil
}

// checkWindowsFileIDOutcome distinguishes an identity mismatch from an unavailable ID.
func checkWindowsFileIDOutcome(t *testing.T, outcome, name string, report *Report, err error) {
	t.Helper()
	switch outcome {
	case "same file":
		if err != nil || !report.Passed() || report.Fixtures != 1 {
			t.Fatalf("stable fixture: report=%+v err=%v", report, err)
		}
	case "high ID changed", "volume changed":
		if report != nil || err == nil || !strings.Contains(err.Error(), "source changed while opening") {
			t.Fatalf("different FILE_ID_INFO: report=%+v err=%v", report, err)
		}
	default:
		requireUnavailableFileID(t, name, report, err)
	}
}

// requireUnavailableFileID requires a named incomplete finding and no certified fixture.
func requireUnavailableFileID(t *testing.T, name string, report *Report, err error) {
	t.Helper()
	if err != nil || report == nil {
		t.Fatalf("unavailable FileIdInfo: report=%+v err=%v", report, err)
	}
	requireSnapshotFinding(t, report, 0, name, "incomplete replay")
	if !strings.Contains(report.Findings[0].Detail, "FileIdInfo") {
		t.Fatalf("missing FileIdInfo diagnostic: %+v", report.Findings)
	}
}
