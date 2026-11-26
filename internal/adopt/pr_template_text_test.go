// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/contextopt"
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
	"policy-limits.md.prior",
	"policy-reference.md.prior",
	"preset.md.prior",
	"scoped-marker.md.prior",
	"unwrapped.md.prior",
	"wrapped.md.prior",
}

// checkPRTemplateFixtures reads at most one entry beyond the recorded inventory.
func checkPRTemplateFixtures(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	entries, err := readVerificationDirectory(ctx, dir, len(priorPRTemplateFiles))
	if err != nil {
		return err
	}
	names := make([]string, len(entries))
	for i := 0; i < len(entries) && i <= len(priorPRTemplateFiles); i++ {
		names[i] = entries[i].Name()
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
	if err := checkPRTemplateFixtures(t.Context(), dir); err == nil {
		t.Fatal("accepted a missing fixture")
	}
	mustWrite(t, filepath.Join(dir, "unknown"), "fixture\n")
	if err := checkPRTemplateFixtures(t.Context(), dir); err == nil {
		t.Fatal("accepted an unknown name in place of the missing fixture")
	}
	mustWrite(t, filepath.Join(dir, priorPRTemplateFiles[0]), "fixture\n")
	if err := checkPRTemplateFixtures(t.Context(), dir); err == nil {
		t.Fatal("accepted an extra fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 0)
	defer cancel()
	if err := checkPRTemplateFixtures(ctx, prTemplateFixtures); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired inventory read returned %v", err)
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
			"Repositories enforcing `forge validate-pr` need a signed receipt before merge.",
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

// adoptTemplateUnderManifest resolves the fixture's catalog and installs the template in a fresh session.
func adoptTemplateUnderManifest(t *testing.T, s *adoptSession, manifest string) *AdoptReport {
	t.Helper()
	mustWrite(t, filepath.Join(s.repoPath, manifestFile), manifest)
	session := &adoptSession{repoPath: s.repoPath, opts: s.opts, report: &AdoptReport{}}
	if err := reconcilePolicyCatalog(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if err := reconcilePullRequestTemplate(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	return session.report
}

// TestPRTemplateReadoptionAfterPolicyChange tightens the pinned repository's McCabe limit.
func TestPRTemplateReadoptionAfterPolicyChange(t *testing.T) {
	for _, tc := range [...]struct {
		name         string
		crlf, edited bool
	}{
		{name: "LF"},
		{name: "CRLF", crlf: true},
		{name: "hand-edited limit", edited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkTemplatePolicyChange(t, tc.crlf, tc.edited)
		})
	}
}

// checkTemplatePolicyChange compares the file bytes and reported action after tightening the policy.
func checkTemplatePolicyChange(t *testing.T, crlf, edited bool) {
	t.Helper()
	s, _ := catalogSession(t)
	manifest := repoText(t, s.repoPath, manifestFile) +
		"overrides:\n  complexity:\n    max_cognitive: 15\n    max_statements: 50\n    max_cyclomatic: "
	adoptTemplateUnderManifest(t, s, manifest+"8\n")
	original := repoText(t, s.repoPath, prTemplateFile)
	template := original
	const installed = "McCabe cyclomatic <= 8 "
	if !strings.Contains(template, installed) {
		t.Fatalf("first adoption lacks %q", installed)
	}
	if crlf {
		template = crlfText(template)
	}
	want := strings.Replace(template, installed, "McCabe cyclomatic <= 7 ", 1)
	if edited {
		template = strings.Replace(template, installed, "McCabe cyclomatic <= 9 ", 1)
		want = template
	}
	if template != original {
		mustWrite(t, filepath.Join(s.repoPath, prTemplateFile), template)
	}
	report := adoptTemplateUnderManifest(t, s, manifest+"7\n")
	if got := repoText(t, s.repoPath, prTemplateFile); got != want {
		t.Errorf("template after tightening differs from the expected %s rendering", t.Name())
	}
	action := report.ActionDetails[len(report.ActionDetails)-1]
	if !strings.EqualFold(action.Path, prTemplateFile) || strings.HasPrefix(action.Details, "Refreshed") == edited {
		t.Errorf("unexpected template action %+v", action)
	}
	if warned(report, action.Path, "kept") != edited {
		t.Errorf("unexpected template drift warnings %q", report.Warnings)
	}
}

// TestPRTemplateInstallRecord binds a verified CRLF copy and leaves its record alone on preview and drift.
func TestPRTemplateInstallRecord(t *testing.T) {
	s := ceilingPRTemplateSession(t.TempDir())
	s.policy.Policy.Complexity.MaxCyclomatic = 8
	installed := crlfText(buildPullRequestTemplate(s.policy.Policy.Complexity))
	// Exercise the existing uppercase path as well as an installation with no prior record.
	mustWrite(t, filepath.Join(s.repoPath, prTemplateUpper), installed)
	record := filepath.Join(s.repoPath, workingDirPath, "adopt-installed", prTemplateUpper+".sha256")
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	want := fixtureDigest(t, prTemplateUpper, []byte(installed)) + "\n"
	if got := mustRead(t, record); got != want {
		t.Fatalf("verified CRLF template install record = %q, want %q", got, want)
	}
	s.policy.Policy.Complexity.MaxCyclomatic = 7
	s.opts.DryRun = true
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, record) != want || repoText(t, s.repoPath, prTemplateUpper) != installed {
		t.Fatal("preview changed the template or its install record")
	}
	s.opts.DryRun = false
	mustWrite(t, filepath.Join(s.repoPath, prTemplateUpper), installed+"Owner edit.\r\n")
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, record) != want {
		t.Fatal("readoption advanced the install record after preserving a hand edit")
	}
	mustWrite(t, filepath.Join(s.repoPath, prTemplateUpper), installed)
	if err := reconcilePullRequestTemplate(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	refreshed := crlfText(buildPullRequestTemplate(s.policy.Policy.Complexity))
	if repoText(t, s.repoPath, prTemplateUpper) != refreshed || mustRead(t, record) != fixtureDigest(t, prTemplateUpper, []byte(refreshed))+"\n" {
		t.Fatal("restoring the installed bytes did not refresh both the template and its digest")
	}
}

// TestPRTemplateRejectsMalformedInstallRecord requires an invalid digest to fail before writing.
func TestPRTemplateRejectsMalformedInstallRecord(t *testing.T) {
	s := ceilingPRTemplateSession(t.TempDir())
	rel := filepath.Join(workingDirPath, "adopt-installed", prTemplateFile+".sha256")
	record := filepath.Join(s.repoPath, rel)
	mustWrite(t, record, "invalid digest\n")
	if err := reconcilePullRequestTemplate(t.Context(), s); err == nil || !strings.Contains(err.Error(), rel) {
		t.Fatalf("malformed install record: got %v, want an error naming the record", err)
	}
	assertAbsent(t, s.repoPath, prTemplateFile)
	if got := mustRead(t, record); got != "invalid digest\n" {
		t.Errorf("malformed record was overwritten with %q", got)
	}
}

// TestPRTemplateBlockedLedger plans without a prior digest and reports the blocked writes on apply.
func TestPRTemplateBlockedLedger(t *testing.T) {
	repo := t.TempDir()
	initTestGit(t, repo)
	writeOriginRemote(t, repo, "https://github.com/acme/widget.git")
	blocked := filepath.Join(repo, workingDirPath)
	mustWrite(t, blocked, "blocked ledger")
	opts := AdoptOptions{Path: repo, LockSourceRoot: newAdoptLockSource(t), SkipHookActivation: true, DryRun: true}
	plan, err := Adopt(t.Context(), opts)
	if err != nil {
		t.Fatalf("plan with blocked ledger: %v", err)
	}
	assertNoIssues(t, plan)
	if !hasAction(plan, prTemplateFile, actionCreate) {
		t.Fatalf("plan omitted the new template %s", prTemplateFile)
	}
	assertAbsent(t, repo, prTemplateFile)

	opts.DryRun = false
	applied, err := Adopt(t.Context(), opts)
	if err != nil {
		t.Fatalf("apply stopped before reporting incomplete work: %v", err)
	}
	record := filepath.Join(workingDirPath, "adopt-installed", prTemplateFile+".sha256")
	messages := strings.Join(applied.Errors, "\n")
	if !strings.Contains(messages, "write template install record "+record) || !strings.Contains(messages, "workingdir init") {
		t.Fatalf("missing blocked writes in the apply report: %v", applied.Errors)
	}
	if mustRead(t, blocked) != "blocked ledger" || repoText(t, repo, prTemplateFile) == "" {
		t.Fatal("expected the installed template and the original ledger obstruction")
	}
}

// TestPRTemplateRefusesSymlinkedLedger requires a named read failure even when the target is empty.
func TestPRTemplateRefusesSymlinkedLedger(t *testing.T) {
	s := ceilingPRTemplateSession(t.TempDir())
	target := linkInRootDir(t, s.repoPath, workingDirPath, "empty")
	record := filepath.Join(workingDirPath, "adopt-installed", prTemplateFile+".sha256")
	for _, dryRun := range []bool{true, false} {
		s.opts.DryRun = dryRun
		err := reconcilePullRequestTemplate(t.Context(), s)
		if err == nil || !strings.Contains(err.Error(), "read template install record "+record) {
			t.Fatalf("dry run %t: expected a refusal naming the record, got %v", dryRun, err)
		}
	}
	assertAbsent(t, s.repoPath, prTemplateFile)
	assertDirEmpty(t, target)
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
	if err := checkPRTemplateFixtures(t.Context(), prTemplateFixtures); err != nil {
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
