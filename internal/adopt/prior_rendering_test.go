package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/managedasset"
	"github.com/cordanaLLM/praetor/internal/util"
)

// readFixtureDir returns every file directly under dir, keyed by its name.
func readFixtureDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fixtures[entry.Name()] = data
	}
	return fixtures
}

// assertPriorDigestsReproduced replays a set of earlier Praetor texts in both directions: every
// fixture under dir is a recognised digest and every digest has a fixture, so the set can
// neither claim bytes nobody can reproduce nor silently stop covering a fixture.
func assertPriorDigestsReproduced(t *testing.T, dir string, digests map[string]string) {
	t.Helper()
	fixtures := readFixtureDir(t, dir)
	seen := make(map[string]bool, len(fixtures))
	for name, data := range fixtures {
		digest := fixtureDigest(t, name, data)
		if _, ok := digests[digest]; !ok {
			t.Errorf("fixture %s (%s) is not a recognised prior rendering", name, digest)
		}
		seen[digest] = true
	}
	for digest, origin := range digests {
		if !seen[digest] {
			t.Errorf("digest %s (%s) has no fixture under %s", digest, origin, dir)
		}
	}
}

// fixtureDigest is the key priorRendering looks data up by.
func fixtureDigest(t *testing.T, name string, data []byte) string {
	t.Helper()
	digest, _, err := util.CanonicalTextDigest(data)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return digest
}

// priorDigestSet records text the way the earlier-text sets do.
func priorDigestSet(t *testing.T, text string) map[string]string {
	t.Helper()
	return map[string]string{fixtureDigest(t, "recorded text", []byte(text)): "fixture"}
}

// TestPriorScaffoldRefreshAfterConcurrentWrite replays two refreshes with the same observation.
func TestPriorScaffoldRefreshAfterConcurrentWrite(t *testing.T) {
	const prior = "prior\n"
	const current = "current\n"
	for _, tc := range [...]struct {
		name, winner string
		confined     bool
	}{
		{"current", current, false},
		{"edited", "user edit\n", false},
		{"confined-current", current, true},
		{"confined-edited", "user edit\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sc := scaffold{rel: "scaffold.md", perm: filePerm, content: []byte(current), confined: tc.confined}
			path := filepath.Join(root, sc.rel)
			mustWrite(t, path, prior)
			s := &adoptSession{repoPath: root}
			if err := s.publishPriorRefresh(t.Context(), path, []byte(prior), []byte(tc.winner), sc); err != nil {
				t.Fatal(err)
			}
			err := s.publishPriorRefresh(t.Context(), path, []byte(prior), sc.content, sc)
			assertRefreshConflict(t, err, tc.winner != current)
			if got := mustRead(t, path); got != tc.winner {
				t.Fatalf("winning bytes changed from %q to %q", tc.winner, got)
			}
		})
	}
}

// assertRefreshConflict distinguishes an expected stale snapshot conflict from other failures.
func assertRefreshConflict(t *testing.T, err error, wantConflict bool) {
	t.Helper()
	if wantConflict {
		if err == nil || !strings.Contains(err.Error(), "snapshot changed before replacement") {
			t.Fatalf("expected a stale snapshot conflict, got %v", err)
		}
	} else if err != nil {
		t.Fatalf("identical winner within ceiling: %v", err)
	}
}

// requireRefreshMode reads the published file's identity and checks its POSIX permissions.
func requireRefreshMode(t *testing.T, path string, want os.FileMode) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode(); got != want {
		t.Fatalf("%s mode = %v, want %v", path, got, want)
	}
	return info
}

// TestPriorScaffoldRefreshPermissionCeiling preserves an identical winner at its published mode.
func TestPriorScaffoldRefreshPermissionCeiling(t *testing.T) {
	if !util.ModeIsProtection() {
		t.Skip("group and other read permissions require POSIX file modes")
	}
	for _, tc := range [...]struct {
		name            string
		winner, ceiling os.FileMode
		conflict        bool
	}{
		{"exceeds", 0o644, 0o600, true},
		{"equals", 0o644, 0o644, false},
		{"more-restrictive", 0o600, 0o644, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &adoptSession{repoPath: t.TempDir()}
			sc := scaffold{rel: "scaffold.md", perm: tc.winner, content: []byte("current\n")}
			path := filepath.Join(s.repoPath, sc.rel)
			prior := []byte("prior\n")
			if err := contextopt.WriteSnapshot(t.Context(), path, prior, tc.winner); err != nil {
				t.Fatal(err)
			}
			if err := s.publishPriorRefresh(t.Context(), path, prior, sc.content, sc); err != nil {
				t.Fatal(err)
			}
			before := requireRefreshMode(t, path, tc.winner)
			sc.perm = tc.ceiling
			err := s.publishPriorRefresh(t.Context(), path, prior, sc.content, sc)
			assertRefreshConflict(t, err, tc.conflict)
			if after := requireRefreshMode(t, path, tc.winner); !os.SameFile(before, after) {
				t.Fatal("stale refresh replaced the winning file")
			}
			if got := mustRead(t, path); got != string(sc.content) {
				t.Fatalf("winning bytes changed to %q", got)
			}
		})
	}
}

// TestPriorScaffoldRefreshAfterRemoval preserves the error when the winner removed the file.
func TestPriorScaffoldRefreshAfterRemoval(t *testing.T) {
	s := &adoptSession{repoPath: t.TempDir()}
	sc := scaffold{rel: "empty.md", perm: filePerm}
	path := filepath.Join(s.repoPath, sc.rel)
	err := s.publishPriorRefresh(t.Context(), path, []byte("prior\n"), sc.content, sc)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed scaffold with an empty target: got %v, want missing file", err)
	}
	assertAbsent(t, s.repoPath, sc.rel)
}

// Positive: the recorded LF text and its CRLF checkout (core.autocrlf on Windows) are both
// recognised, and the CRLF one is reported as such so a refresh can keep its style (HISS-21).
func TestIsPriorRendering_Positive_EitherConsistentLineEndingStyle(t *testing.T) {
	const text = "version: 1\nname: x\n"
	digests := priorDigestSet(t, text)
	if known, crlf := priorRendering([]byte(text), digests); !known || crlf {
		t.Errorf("the recorded LF text: known=%v crlf=%v", known, crlf)
	}
	if known, crlf := priorRendering([]byte(crlfText(text)), digests); !known || !crlf {
		t.Errorf("the CRLF checkout of the recorded text: known=%v crlf=%v", known, crlf)
	}
	if !isPriorRendering([]byte(crlfText(text)), digests) {
		t.Error("isPriorRendering must apply the same rule as priorRendering")
	}
}

// Negative: an edited copy is not a prior rendering, in either line-ending style.
func TestIsPriorRendering_Negative_EditedCopies(t *testing.T) {
	const text = "version: 1\n"
	digests := priorDigestSet(t, text)
	for name, edited := range map[string]string{
		"LF, one line more":   text + "\n",
		"CRLF, one line more": "version: 1\r\n\r\n",
		"CRLF, value changed": "version: 2\r\n",
	} {
		if isPriorRendering([]byte(edited), digests) {
			t.Errorf("%s: an edited copy was recognised", name)
		}
	}
}

// Boundary: mixed line endings and lone carriage returns match nothing, even when the LF text
// underneath is the recorded one, and empty data or an empty digest set match nothing.
func TestIsPriorRendering_Boundary_MixedEndingsAndEmptyInputs(t *testing.T) {
	const text = "version: 1\nname: x\n"
	digests := priorDigestSet(t, text)
	for _, mixed := range []string{"version: 1\r\nname: x\n", "version: 1\rname: x\n"} {
		if known, _ := priorRendering([]byte(mixed), digests); known {
			t.Errorf("%q: mixed line endings were recognised", mixed)
		}
	}
	if isPriorRendering(nil, digests) || isPriorRendering([]byte(text), nil) {
		t.Error("empty data and an empty digest set match nothing")
	}
}

// Positive: the managed asset families' Prior is read by the same rule as adoption's
// earlier-text sets (HISS-19). Every earlier documentation-gate text reproduces a Prior key
// through fixtureDigest, and priorRendering and Family.PriorRendering agree on it, CRLF flag
// included, in both line-ending styles; an edited copy is refused by both.
func TestPriorRendering_Positive_SharesTheManagedFamilyRule(t *testing.T) {
	family := managedasset.ForFacet(managedasset.DocumentationFacet)[0]
	dir := filepath.Join("..", "..", "tools", "markdownlint", "testdata", "prior")
	assertPriorDigestsReproduced(t, dir, family.Prior)
	for name, data := range readFixtureDir(t, dir) {
		lf, _, err := util.NormalizeLineEndingsStrict(string(data))
		if err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		rel := family.Prior[fixtureDigest(t, name, data)]
		for _, text := range []string{lf, crlfText(lf), crlfText(lf + "# edited\n")} {
			known, crlf := priorRendering([]byte(text), family.Prior)
			familyKnown, familyCRLF := family.PriorRendering(rel, []byte(text))
			if known != familyKnown || crlf != familyCRLF {
				t.Errorf("%s: adoption says known=%v crlf=%v, the family says known=%v crlf=%v",
					name, known, crlf, familyKnown, familyCRLF)
			}
		}
	}
}
