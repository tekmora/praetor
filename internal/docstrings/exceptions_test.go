// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package docstrings

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/cifilter"
	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/testsupport"
	"github.com/cordanaLLM/praetor/internal/util"
)

// TestDocstringExceptions verifies that only a live content-pinned entry excuses a counted file.
func TestDocstringExceptions(t *testing.T) {
	data, err := os.ReadFile("testdata/undocumented.py")
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	today := time.Now().UTC()
	cases := []struct {
		name, fingerprint, entered, expires, status string
		passed                                      bool
		counted                                     int
	}{
		{"unlisted snapshot fails", "", "", "", "", false, 1},
		{"listed snapshot passes", hash[:8], today.Format(time.DateOnly), today.AddDate(0, 0, 120).Format(time.DateOnly), "excepted", true, 0},
		{"expired snapshot fails", hash[:8], "", today.AddDate(0, 0, -1).Format(time.DateOnly), "expired", false, 1},
		{"stale snapshot fails", strings.Repeat("0", 8), "", today.Format(time.DateOnly), "stale", false, 1},
		{"expiry day inclusive", hash, "", today.Format(time.DateOnly), "excepted", true, 0},
		{"uppercase prefix passes", strings.ToUpper(hash[:8]), "", today.Format(time.DateOnly), "excepted", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeDocstringExceptionFixture(t, data, tc.fingerprint, tc.entered, tc.expires)
			if tc.entered != "" {
				assertExceptionValidOn(t, root, today.AddDate(0, 0, -1))
			}
			rep, err := evaluateChangedFiles(t.Context(), root, "", Config{Mode: "error", Threshold: 80}, map[string][]cifilter.LineRange{"snapshot.py": {{Start: 1, End: 10}}})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Passed != tc.passed || rep.Covered != 0 || rep.Counted != tc.counted || len(rep.Uncovered) != tc.counted {
				t.Fatalf("passed=%v counted=%d covered=%d; want passed=%v", rep.Passed, rep.Counted, rep.Covered, tc.passed)
			}
			assertDocstringException(t, rep.Exceptions, tc.status, tc.expires)
		})
	}
}

// assertExceptionValidOn checks the manifest when the validator's local date is still yesterday.
func assertExceptionValidOn(t *testing.T, root string, localDay time.Time) {
	t.Helper()
	manifest, err := config.LoadManifest(filepath.Join(root, config.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateExceptions(manifest.Exceptions, localDay); err != nil {
		t.Fatalf("validate the 120-day fixture on %s: %v", localDay.Format(time.DateOnly), err)
	}
}

// TestDocstringExceptions_CommittedHead checks the exact blob and manifest at the selected head.
func TestDocstringExceptions_CommittedHead(t *testing.T) {
	data, err := os.ReadFile("testdata/undocumented.py")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	cases := []struct {
		name                     string
		headEntry, checkoutEntry bool
		counted                  int
		status                   string
	}{
		{"committed newline", true, true, 0, "excepted"},
		{"head only", true, false, 0, "excepted"},
		{"checkout only", false, true, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeDocstringExceptionFixture(t, data, fmt.Sprintf("%x", sha256.Sum256(data)), "", expires)
			rep := checkCommittedExceptionFixture(t, root, tc.headEntry, tc.checkoutEntry)
			if rep.Passed != tc.headEntry || rep.Counted != tc.counted || len(rep.Uncovered) != tc.counted {
				t.Fatalf("want passed=%v and %d uncovered, got %+v", tc.headEntry, tc.counted, rep)
			}
			assertDocstringException(t, rep.Exceptions, tc.status, expires)
		})
	}
}

// checkCommittedExceptionFixture checks HEAD after independently setting the two manifest states.
func checkCommittedExceptionFixture(t *testing.T, root string, headEntry, checkoutEntry bool) *Report {
	t.Helper()
	testsupport.InitGitRepoWithOrigin(t, root, "")
	testsupport.RunFixtureGit(t, root,
		[]string{"commit", "--allow-empty", "-m", "empty base"},
		[]string{"add", "snapshot.py"})
	if headEntry {
		testsupport.RunFixtureGit(t, root, []string{"add", config.ManifestFileName})
	}
	testsupport.RunFixtureGit(t, root, []string{"commit", "-m", "add snapshot"})
	if !checkoutEntry {
		if err := os.Remove(filepath.Join(root, config.ManifestFileName)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, err := util.WithCommandEnvironment(t.Context(), testsupport.HermeticGitEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Check(ctx, Options{RepoDir: root, BaseRef: "HEAD^", HeadRef: "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestDocstringExceptions_UncountedFile verifies that entries for untouched declarations stay unreported.
func TestDocstringExceptions_UncountedFile(t *testing.T) {
	data := []byte("def untouched():\n    return 1\n")
	root := writeDocstringExceptionFixture(t, data, fmt.Sprintf("%x", sha256.Sum256(data)), "", time.Now().UTC().Format(time.DateOnly))
	rep, err := evaluateChangedFiles(t.Context(), root, "", Config{Mode: "error", Threshold: 80}, map[string][]cifilter.LineRange{"snapshot.py": {{Start: 10, End: 11}}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed || rep.Counted != 0 || len(rep.Exceptions) != 0 {
		t.Fatalf("untouched declarations affected report: %+v", rep)
	}
}

// writeDocstringExceptionFixture plants a source file and optionally its manifest exception.
func writeDocstringExceptionFixture(t *testing.T, data []byte, fingerprint, entered, expires string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "snapshot.py"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if fingerprint != "" {
		body := fmt.Sprintf("version: 1\nexceptions:\n  - rule: docstrings\n    path: snapshot.py\n    fingerprint: %s\n    category: D\n    reason: prior rendering fixture\n    expires: %s\n", fingerprint, expires)
		if entered != "" {
			body += "    entered: " + entered + "\n"
		}
		if err := os.WriteFile(filepath.Join(root, config.ManifestFileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// assertDocstringException checks the visible disposition or absence of a file exception.
func assertDocstringException(t *testing.T, entries []ExceptionEntry, status, expires string) {
	t.Helper()
	if status == "" {
		if len(entries) != 0 {
			t.Fatalf("unlisted file acquired exceptions: %+v", entries)
		}
		return
	}
	want := ExceptionEntry{Path: "snapshot.py", Category: "D", Expires: expires, Status: status}
	if len(entries) != 1 || entries[0] != want {
		t.Fatalf("exceptions=%+v, want %+v", entries, want)
	}
}
