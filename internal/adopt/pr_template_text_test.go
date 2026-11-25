// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const prTemplateFixtures = "testdata/pr-template"

// prTemplateOpsMarker is replaced verbatim when ops fills the PR description.
const prTemplateOpsMarker = "<!-- Provide a concise description of what this PR introduces, refactors, or fixes. -->"

// prTemplateMarkerBlock limits the width exception to the ops marker.
const prTemplateMarkerBlock = "<!-- markdownlint-disable MD013 -->\n" + prTemplateOpsMarker + "\n<!-- markdownlint-enable MD013 -->"

// priorPRTemplateFiles lists the recorded renderings in filename order.
var priorPRTemplateFiles = [...]string{
	"concise.md.prior",
	"hiss-16.md.prior",
	"hiss.md.prior",
	"preset.md.prior",
	"unwrapped.md.prior",
	"wrapped.md.prior",
}

// checkPRTemplateFixtures reads at most one entry beyond the recorded inventory.
func checkPRTemplateFixtures(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, readErr := f.Readdirnames(len(priorPRTemplateFiles) + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	slices.Sort(names)
	if !slices.Equal(names, priorPRTemplateFiles[:]) {
		return fmt.Errorf("prior PR template fixtures: found %v, want %v", names, priorPRTemplateFiles)
	}
	return nil
}

// TestPriorPRTemplateFixtureInventory rejects missing, substituted and extra entries.
func TestPriorPRTemplateFixtureInventory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range priorPRTemplateFiles[1:] {
		mustWrite(t, filepath.Join(dir, name), "fixture\n")
	}
	if err := checkPRTemplateFixtures(dir); err == nil {
		t.Fatal("accepted a missing fixture")
	}
	mustWrite(t, filepath.Join(dir, "unknown"), "fixture\n")
	if err := checkPRTemplateFixtures(dir); err == nil {
		t.Fatal("accepted an unknown name in place of the missing fixture")
	}
	mustWrite(t, filepath.Join(dir, priorPRTemplateFiles[0]), "fixture\n")
	if err := checkPRTemplateFixtures(dir); err == nil {
		t.Fatal("accepted an extra fixture")
	}
}

// TestPRTemplateMatchesScaffold guards the engine's copy byte for byte.
func TestPRTemplateMatchesScaffold(t *testing.T) {
	if got := repoText(t, sourceCheckout, prTemplateFile); got != buildPullRequestTemplate() {
		t.Fatalf("%s differs from buildPullRequestTemplate()", prTemplateFile)
	}
}

// TestPRTemplatesRequestActualTestResult checks both copies and replays the prefilled template.
func TestPRTemplatesRequestActualTestResult(t *testing.T) {
	root, plan := verificationFixture(t, map[string]string{"Cargo.toml": cargoToml})
	if len(plan.Test) != 1 || !slices.Equal(plan.Test[0], []string{"cargo", "test", "--locked"}) {
		t.Fatalf("Cargo-only fixture selected test commands %q", plan.Test)
	}
	cargo := installedPRTemplate(t, root, plan)
	if command := regexp.MustCompile(`\bgo[ \t]+\w+`).FindString(cargo); command != "" {
		t.Errorf("Cargo-only template names the Go command %q", command)
	}
	const prompt = "\n- [ ] Record the test command you ran and its outcome.\n"
	for _, tc := range [...]struct {
		name, body string
		wantPrompt bool
	}{
		{"engine", repoText(t, sourceCheckout, prTemplateFile), true},
		{"Cargo-only adopter", cargo, true},
		{"prefilled result plus prompt", mustRead(t, filepath.Join(prTemplateFixtures, "preset.md.prior")) + prompt, false},
	} {
		hasPrompt := strings.Contains(tc.body, prompt) && !strings.Contains(tc.body, "(PASS)")
		if hasPrompt != tc.wantPrompt {
			t.Errorf("%s: unchecked command and outcome prompt without a prefilled result = %t, want %t", tc.name, hasPrompt, tc.wantPrompt)
		}
	}
}

// TestPRTemplateSocialTextHeading ties the writing instructions to the preset heading.
func TestPRTemplateSocialTextHeading(t *testing.T) {
	want := "prose under `" + prDescriptionHeading + "`"
	if !strings.Contains(sourceSkillText(t, "social-text"), want) {
		t.Fatalf("social-text must direct authors to %s", prDescriptionHeading)
	}
	previous := filepath.Join(priorSkillFixtures, "social-text", "ship-70.SKILL.md.prior")
	if strings.Contains(mustRead(t, previous), want) {
		t.Fatal("the prior skill unexpectedly satisfies the updated heading check")
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
	if !ok || description != "# Pull Request\n\n"+prDescriptionHeading+"\n\n"+prTemplateMarkerBlock+"\n" {
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
	for _, name := range priorPRTemplateFiles {
		data := mustRead(t, filepath.Join(prTemplateFixtures, name))
		digest := fixtureDigest(t, name, []byte(data))
		if _, ok := older[digest]; !ok {
			t.Fatalf("%s has an unknown or duplicate digest %s", name, digest)
		}
		delete(older, digest)
	}
	if len(older) != 0 {
		t.Fatalf("prior renderings without a fixture: %v", older)
	}
}

// TestForgeText_PriorTemplate verifies readoption of every shipped version in an adopter's checkout.
func TestForgeText_PriorTemplate(t *testing.T) {
	current := buildPullRequestTemplate()
	if err := checkPRTemplateFixtures(prTemplateFixtures); err != nil {
		t.Fatal(err)
	}
	for _, name := range priorPRTemplateFiles {
		prior := mustRead(t, filepath.Join(prTemplateFixtures, name))
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
