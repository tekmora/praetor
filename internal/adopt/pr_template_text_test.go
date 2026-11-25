// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"maps"
	"path/filepath"
	"strings"
	"testing"
)

const prTemplateFixtures = "testdata/pr-template"

// TestPRTemplateMatchesScaffold guards the engine's copy byte for byte.
func TestPRTemplateMatchesScaffold(t *testing.T) {
	if got := repoText(t, sourceCheckout, prTemplateFile); got != buildPullRequestTemplate() {
		t.Fatalf("%s differs from buildPullRequestTemplate()", prTemplateFile)
	}
}

// missingPresetHeading returns the first required heading absent from the rendered template.
func missingPresetHeading(body string) string {
	for _, heading := range []string{prDescriptionHeading, prChecklistHeading} {
		offset := headingLineOffset(body, heading)
		if offset < 0 || !strings.HasPrefix(body[offset:], heading+"\n") {
			return heading
		}
	}
	return ""
}

// TestPRTemplatePresetHeadings requires both headings, even if a missing one is quoted in a fence.
func TestPRTemplatePresetHeadings(t *testing.T) {
	body := buildPullRequestTemplate()
	for name, template := range map[string]string{
		"scaffold":     body,
		prTemplateFile: repoText(t, sourceCheckout, prTemplateFile),
	} {
		if missing := missingPresetHeading(template); missing != "" {
			t.Errorf("%s lacks %q", name, missing)
		}
	}
	for _, heading := range []string{prDescriptionHeading, prChecklistHeading} {
		for _, replacement := range []string{"", "```markdown\n" + heading + "\n```\n"} {
			planted := strings.Replace(body, heading+"\n", replacement, 1)
			if got := missingPresetHeading(planted); got != heading {
				t.Errorf("replacing %q with %q reported missing heading %q", heading, replacement, got)
			}
		}
	}
}

// TestPRTemplateChecklistLayout protects the ops replacement marker and the checklist hierarchy.
func TestPRTemplateChecklistLayout(t *testing.T) {
	body := buildPullRequestTemplate()
	description, checklist, ok := strings.Cut(body, "\n"+prChecklistHeading+"\n")
	const placeholder = "<!-- Provide a concise description of what this PR introduces, refactors, or fixes. -->"
	if !ok || description != "# Pull Request\n\n"+prDescriptionHeading+"\n\n"+placeholder+"\n" {
		t.Fatal("expected the title and description placeholder immediately before the checklist")
	}
	intro, _, _ := strings.Cut(checklist, "\n### ")
	if got := strings.Count(intro, "\n- [ ] "); got != 5 {
		t.Errorf("checklist starts with %d checkboxes, want 5", got)
	}
	for _, section := range []string{"### 1. ", "### 2. ", "### 3. ", "### 4. "} {
		offset := headingLineOffset(checklist, section)
		if offset < 0 {
			t.Fatalf("missing or out-of-order checklist section %q", section)
		}
		checklist = checklist[offset+len(section):]
	}
}

// TestPriorPRTemplateDigests records the current rendering and replays each older fixture.
func TestPriorPRTemplateDigests(t *testing.T) {
	current := fixtureDigest(t, prTemplateFile, []byte(buildPullRequestTemplate()))
	if _, ok := priorPRTemplateDigests[current]; !ok {
		t.Fatalf("current scaffold digest %s is missing from priorPRTemplateDigests", current)
	}
	older := maps.Clone(priorPRTemplateDigests)
	delete(older, current)
	assertPriorDigestsReproduced(t, prTemplateFixtures, older)
}

// TestForgeText_PriorTemplate verifies readoption of every shipped version in an adopter's checkout.
func TestForgeText_PriorTemplate(t *testing.T) {
	current := buildPullRequestTemplate()
	for name, data := range readFixtureDir(t, prTemplateFixtures) {
		prior := string(data)
		edited := prior + "Custom paragraph.\n"
		for _, tc := range []struct {
			name, before, want string
			refresh            bool
		}{
			{"LF", prior, current, true},
			{"CRLF", crlfText(prior), crlfText(current), true},
			{"edited", edited, edited, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, prTemplateFile)
				mustWrite(t, path, tc.before)
				s := &adoptSession{repoPath: root, report: &AdoptReport{}}
				if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
					t.Fatal(err)
				}
				detail := findActionDetail(s.report.ActionDetails, prTemplateFile)
				if strings.HasPrefix(detail, "Refreshed") != tc.refresh {
					t.Errorf("refresh = %t expected, adoption reported %q", tc.refresh, detail)
				}
				if got := mustRead(t, path); got != tc.want {
					t.Fatalf("after readoption got %q, want %q", got, tc.want)
				}
			})
		}
	}
}
