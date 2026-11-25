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

	"github.com/cordanaLLM/praetor/internal/config"
)

const prTemplateFixtures = "testdata/pr-template"

// prTemplateOpsMarker is replaced verbatim when ops fills the PR description.
const prTemplateOpsMarker = "<!-- Provide a concise description of what this PR introduces, refactors, or fixes. -->"

// prTemplateMarkerBlock limits the width exception to the ops marker.
const prTemplateMarkerBlock = "<!-- markdownlint-capture -->\n<!-- markdownlint-disable MD013 -->\n" + prTemplateOpsMarker + "\n<!-- markdownlint-restore -->"

// priorPRTemplateFiles lists the recorded renderings in filename order.
var priorPRTemplateFiles = [...]string{
	"concise.md.prior",
	"hiss-16.md.prior",
	"hiss.md.prior",
	"policy-reference.md.prior",
	"preset.md.prior",
	"scoped-marker.md.prior",
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

// TestPRTemplateMatchesScaffold compares the engine's copy with adoption under its pinned policy.
func TestPRTemplateMatchesScaffold(t *testing.T) {
	policy, err := config.LoadEffectivePolicyContext(t.Context(), config.EffectiveOptions{Root: sourceCheckout, Audit: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}, policy: policy}
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if repoText(t, sourceCheckout, prTemplateFile) != repoText(t, s.repoPath, prTemplateFile) {
		t.Fatalf("%s differs from adoption under the engine's audit policy", prTemplateFile)
	}
}

// TestPRTemplateUnresolvedPolicy refuses a live write and identifies the omitted dry-run preview.
func TestPRTemplateUnresolvedPolicy(t *testing.T) {
	s := &adoptSession{repoPath: t.TempDir(), report: &AdoptReport{}}
	if err := reconcilePullRequestTemplate(t.Context(), s); err == nil || !strings.Contains(err.Error(), "effective audit policy is unresolved") {
		t.Fatalf("unresolved policy: got %v, want a named policy error", err)
	}
	assertAbsent(t, s.repoPath, prTemplateFile)
	s.opts.DryRun = true
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	action := findLastAction(s.report.ActionDetails, prTemplateFile)
	if action == nil || action.Action != actionSkip || !strings.Contains(action.Details, "requires the resolved audit policy") {
		t.Errorf("unresolved preview: got %+v, want a skipped template with the policy reason", action)
	}
	assertAbsent(t, s.repoPath, prTemplateFile)
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

// TestPRTemplateReceiptInstructions covers a Python-only adopter and the engine's signed receipt.
func TestPRTemplateReceiptInstructions(t *testing.T) {
	root, plan := verificationFixture(t, map[string]string{"pyproject.toml": "[tool.pytest.ini_options]\n"})
	if !slices.Equal(plan.Runtimes, []string{"python"}) {
		t.Fatalf("expected Python-only fixture, got runtimes %q", plan.Runtimes)
	}
	for _, tc := range [...]struct{ name, body string }{
		{"Python-only adopter", installedPRTemplate(t, root, plan)},
		{"engine", repoText(t, sourceCheckout, prTemplateFile)},
	} {
		for _, want := range [...]string{
			"If the gate signs a receipt for this head, paste its JSON in the fence below.",
			"Otherwise, record which verification ran and the reason the gate reported.",
			"`.standards-receipt.json`",
			"If pre-push kept a copy",
			"\n```receipt\n```\n",
		} {
			if !strings.Contains(tc.body, want) {
				t.Errorf("%s template lacks %q", tc.name, want)
			}
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
	body := installedPRTemplate(t, t.TempDir(), nil)
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
	body := installedPRTemplate(t, t.TempDir(), nil)
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

// TestPRTemplateDefaultLimits checks a pinned catalog that declares no complexity limits.
func TestPRTemplateDefaultLimits(t *testing.T) {
	s, _ := catalogSession(t)
	if err := reconcilePolicyCatalog(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	defaults := config.DefaultPolicy().Complexity
	want := fmt.Sprintf("  - Function LOC <= %d and statements <= %d.\n  - McCabe cyclomatic <= %d and cognitive <= %d.\n",
		defaults.MaxFuncLOC, defaults.MaxStatements, defaults.MaxCyclomatic, defaults.MaxCognitive)
	if !strings.Contains(repoText(t, s.repoPath, prTemplateFile), want) {
		t.Errorf("default checklist lacks %q", want)
	}
}

// TestPriorPRTemplateDigests records the current rendering and replays each older fixture.
func TestPriorPRTemplateDigests(t *testing.T) {
	current := fixtureDigest(t, prTemplateFile, []byte(repoText(t, sourceCheckout, prTemplateFile)))
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
	current := installedPRTemplate(t, t.TempDir(), nil)
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
				s := ceilingPRTemplateSession(root)
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
