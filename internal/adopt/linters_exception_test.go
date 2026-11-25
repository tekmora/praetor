// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
)

// Positive: fresh adoption writes exceptions entries for declared linters that adoption
// scaffolds no CI jobs for, and the declared-linters gate passes with excused lines.
func TestAdopt_DeclaredLintersExceptionsFreshAdoption(t *testing.T) {
	ctx := t.Context()
	repoPath := newTestRepo(t, "fresh-adopt-linters")
	mustWrite(t, filepath.Join(repoPath, "main.go"), "package main\n\nfunc main() {}\n")

	source := newLintersLockSource(t)
	rep := adoptWithSource(t, repoPath, source, false)

	manifestData, err := os.ReadFile(filepath.Join(repoPath, manifestFile))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifest, err := config.DecodeManifest(manifestData)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	today := time.Now()
	if err := config.ValidateExceptions(manifest.Exceptions, today); err != nil {
		t.Fatalf("exceptions in fresh manifest failed validation: %v", err)
	}

	linterExceptions := config.ExceptionsFor(manifest.Exceptions, config.ExceptionRuleDeclaredLinters)
	if len(linterExceptions) == 0 {
		t.Fatalf("expected declared-linters exceptions in fresh adoption, got none")
	}

	for i := 0; i < len(linterExceptions) && i < config.MaxExceptions; i++ {
		entry := linterExceptions[i]
		if !strings.Contains(entry.Reason, "adoption scaffolds no CI job for") {
			t.Errorf("entry %s has unexpected reason: %s", entry.Tool, entry.Reason)
		}
	}

	policy := rep.EffectivePolicy
	if policy == nil {
		t.Fatalf("expected EffectivePolicy in adoption report, got nil")
	}

	out, err := AuditDeclaredLinters(ctx, DeclaredLintersOptions{
		RootDir:    repoPath,
		Policy:     policy,
		Exceptions: manifest.Exceptions,
		Today:      today,
	})
	if err != nil {
		t.Fatalf("AuditDeclaredLinters failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[PASS]") || !strings.Contains(out, "excepted") {
		t.Fatalf("expected audit to pass with excepted lines, got:\n%s", out)
	}
}

// Negative: a fixture whose workflow already runs gitleaks gets no gitleaks exception entry.
func TestAdopt_DeclaredLintersWorkflowRunsLinterGetsNoEntry(t *testing.T) {
	repoPath := newTestRepo(t, "workflow-runs-linter")
	mustWrite(t, filepath.Join(repoPath, "main.go"), "package main\n\nfunc main() {}\n")
	mustWrite(t, filepath.Join(repoPath, ".github", "workflows", "security.yml"), `name: Security
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: gitleaks detect --verbose --log-opts="--full-history --all -m"
`)

	source := newLintersLockSource(t)
	adoptWithSource(t, repoPath, source, false)
	exceptions := readDeclaredLinterExceptions(t, repoPath)
	if len(exceptions) == 0 {
		t.Fatalf("expected declared-linters exceptions for other linters, got none")
	}
	for i := 0; i < len(exceptions) && i < config.MaxExceptions; i++ {
		if exceptions[i].Tool == "gitleaks" {
			t.Fatalf("found gitleaks exception when workflow already runs it: %+v", exceptions[i])
		}
	}
}

// Re-adoption keeps existing live entries without duplication.
func TestAdopt_DeclaredLintersReAdoptPreservesEntries(t *testing.T) {
	repoPath := newTestRepo(t, "readopt-preserves")
	mustWrite(t, filepath.Join(repoPath, "main.go"), "package main\n\nfunc main() {}\n")

	source := newLintersLockSource(t)
	adoptWithSource(t, repoPath, source, false)
	initialExceptions := readDeclaredLinterExceptions(t, repoPath)
	if len(initialExceptions) == 0 {
		t.Fatalf("expected initial declared-linters exceptions, got 0")
	}

	adoptWithSource(t, repoPath, source, true)
	readoptExceptions := readDeclaredLinterExceptions(t, repoPath)
	if len(readoptExceptions) != len(initialExceptions) {
		t.Fatalf("re-adoption duplicated or dropped entries: before %d, after %d", len(initialExceptions), len(readoptExceptions))
	}
}

// Re-adoption drops entries for linters that are now run by workflows.
func TestAdopt_DeclaredLintersReAdoptDropsWhenWorkflowAdded(t *testing.T) {
	repoPath := newTestRepo(t, "readopt-drops")
	mustWrite(t, filepath.Join(repoPath, "main.go"), "package main\n\nfunc main() {}\n")

	source := newLintersLockSource(t)
	adoptWithSource(t, repoPath, source, false)
	initialExceptions := readDeclaredLinterExceptions(t, repoPath)
	initialCount := len(initialExceptions)
	if initialCount == 0 {
		t.Fatalf("expected initial declared-linters exceptions, got 0")
	}

	mustWrite(t, filepath.Join(repoPath, ".github", "workflows", "security.yml"), `name: Security
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: gitleaks detect --verbose --log-opts="--full-history --all -m"
`)
	adoptWithSource(t, repoPath, source, true)
	afterExceptions := readDeclaredLinterExceptions(t, repoPath)
	for i := 0; i < len(afterExceptions) && i < config.MaxExceptions; i++ {
		if afterExceptions[i].Tool == "gitleaks" {
			t.Fatalf("gitleaks exception not dropped after adding workflow: %+v", afterExceptions[i])
		}
	}
	if len(afterExceptions) != initialCount-1 {
		t.Fatalf("expected count %d after dropping gitleaks, got %d", initialCount-1, len(afterExceptions))
	}
}

func newLintersLockSource(t *testing.T) string {
	t.Helper()
	bodies := map[string]string{
		"security:high": "id: \"security:high\"\nname: \"Security High\"\nlinters:\n  - gitleaks\n  - semgrep\n  - trivy\n",
		"template-seed": "id: \"template-seed\"\nname: \"Template Seed\"\nlinters:\n  - govet\n",
	}
	return newCatalogLockSource(t, &config.Manifest{Version: 1,
		Profiles: []string{"framework", "template-seed", "native-gpu-systems", "app-service", "os-image"},
		Facets:   []string{"security:high", "api:public-contract", "docs:seo-portal", "agent:sandboxed", "custom:facet"}}, bodies)
}

func readDeclaredLinterExceptions(t *testing.T, repoPath string) []config.Exception {
	t.Helper()
	manifestData, err := os.ReadFile(filepath.Join(repoPath, manifestFile))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifest, err := config.DecodeManifest(manifestData)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return config.ExceptionsFor(manifest.Exceptions, config.ExceptionRuleDeclaredLinters)
}

// reconcileLintersCase describes one table case over reconcileLintersExceptionsList.
type reconcileLintersCase struct {
	name               string
	existing           []config.Exception
	missing            []config.DeclaredLinter
	today              time.Time
	want               []config.Exception
	wantChanged        bool
	wantExpired        []config.Exception
	wantValid          bool
	wantAuditUnexcused bool
}

// TestReconcileLintersExceptionsList verifies first adoption, live re-adoption, the exact
// Exception.Expired day boundary, expired preservation without renewal, restored-tool removal,
// manual operator renewal, duplicate collapse, and post-reconciliation audit failure.
func TestReconcileLintersExceptionsList(t *testing.T) {
	assertExceptionExpiredBoundary(t)
	cases := append(reconcileLintersLifecycleCases(), reconcileLintersEdgeCases()...)
	for i := 0; i < len(cases) && i < config.MaxExceptions; i++ {
		tc := cases[i]
		t.Run(tc.name, func(t *testing.T) {
			assertReconcileLintersCase(t, tc)
		})
	}
}

// assertExceptionExpiredBoundary pins which side of the date boundary config.Exception.Expired
// puts today on: an entry holds through its expires day and expires on the day after.
func assertExceptionExpiredBoundary(t *testing.T) {
	t.Helper()
	entry := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "waiver", Expires: "2026-10-10"}
	onExpiresDay := time.Date(2026, time.October, 10, 23, 59, 59, 0, time.UTC)
	dayAfterExpiry := time.Date(2026, time.October, 11, 0, 0, 0, 0, time.UTC)
	if entry.Expired(onExpiresDay) {
		t.Fatal("entry expiring today must still hold per config.Exception.Expired")
	}
	if !entry.Expired(dayAfterExpiry) {
		t.Fatal("entry must be expired on the calendar day after expires")
	}
}

// assertReconcileLintersCase runs reconcileLintersExceptionsList and checks the resulting list,
// changed flag, ValidateExceptions, config.ExpiredExceptions, and judgeDeclaredLinters.
func assertReconcileLintersCase(t *testing.T, tc reconcileLintersCase) {
	t.Helper()
	got, changed := reconcileLintersExceptionsList(tc.existing, tc.missing, tc.today)
	if changed != tc.wantChanged {
		t.Fatalf("changed = %v, want %v (got %+v)", changed, tc.wantChanged, got)
	}
	if !sameExceptions(got, tc.want) {
		t.Fatalf("reconcileLintersExceptionsList =\n  %+v\nwant\n  %+v", got, tc.want)
	}
	if tc.wantValid {
		if err := config.ValidateExceptions(got, tc.today); err != nil {
			t.Fatalf("ValidateExceptions failed: %v", err)
		}
	}
	if expired := config.ExpiredExceptions(got, tc.today); !sameExceptions(expired, tc.wantExpired) {
		t.Fatalf("ExpiredExceptions = %+v, want %+v", expired, tc.wantExpired)
	}
	judged := judgeDeclaredLinters(tc.missing, got, tc.today)
	if (len(judged.unexcused) > 0) != tc.wantAuditUnexcused {
		t.Fatalf("judgeDeclaredLinters unexcused = %+v, wantAuditUnexcused = %v", judged.unexcused, tc.wantAuditUnexcused)
	}
}

// sameExceptions compares two exception slices while treating nil and empty slices as equal.
func sameExceptions(got, want []config.Exception) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

// reconcileLintersLifecycleCases returns the core lifecycle and expiry-boundary table cases.
func reconcileLintersLifecycleCases() []reconcileLintersCase {
	today := time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC)
	linter := config.DeclaredLinter{Name: "gitleaks", Source: "facet security:high"}
	missing := []config.DeclaredLinter{linter}
	scaffolded := newDeclaredLinterException(linter, today)
	liveTomorrow := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "waived", Expires: "2026-10-11"}
	onBoundary := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "boundary waiver", Expires: "2026-10-10"}
	pastDeadline := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "C", Entered: "2026-09-01", Reason: "category C: rollout #99", Expires: "2026-09-11"}
	renewed := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "C", Entered: "2026-10-09", Reason: "category C: workflow PR #142 in review", Expires: "2026-10-19"}
	return []reconcileLintersCase{
		{name: "first adoption missing tool scaffolds category-D entry", missing: missing, today: today, want: []config.Exception{scaffolded}, wantChanged: true, wantValid: true},
		{name: "live re-adoption expiring tomorrow stays unchanged", existing: []config.Exception{liveTomorrow}, missing: missing, today: today, want: []config.Exception{liveTomorrow}, wantValid: true},
		{name: "boundary expiring today holds as live", existing: []config.Exception{onBoundary}, missing: missing, today: time.Date(2026, time.October, 10, 23, 59, 59, 0, time.UTC), want: []config.Exception{onBoundary}, wantValid: true},
		{name: "boundary day after expiry keeps expired entry unchanged", existing: []config.Exception{onBoundary}, missing: missing, today: time.Date(2026, time.October, 11, 0, 0, 0, 0, time.UTC), want: []config.Exception{onBoundary}, wantExpired: []config.Exception{onBoundary}, wantValid: true, wantAuditUnexcused: true},
		{name: "expired past deadline keeps entry unchanged without renewal", existing: []config.Exception{pastDeadline}, missing: missing, today: today, want: []config.Exception{pastDeadline}, wantExpired: []config.Exception{pastDeadline}, wantValid: true, wantAuditUnexcused: true},
		{name: "explicit renewal kept as written", existing: []config.Exception{renewed}, missing: missing, today: today, want: []config.Exception{renewed}, wantValid: true},
	}
}

// reconcileLintersEdgeCases returns the restored-tool, duplicate-collapse, and mixed-rule cases.
func reconcileLintersEdgeCases() []reconcileLintersCase {
	today := time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC)
	linter := config.DeclaredLinter{Name: "gitleaks", Source: "facet security:high"}
	missing := []config.DeclaredLinter{linter}
	liveA := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "first live", Expires: "2026-10-20"}
	liveB := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "second live", Expires: "2026-11-20"}
	expA := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "first expired", Expires: "2026-10-09"}
	expB := config.Exception{Rule: config.ExceptionRuleDeclaredLinters, Tool: "gitleaks", Category: "D", Reason: "second expired", Expires: "2026-10-05"}
	supply := config.Exception{Rule: config.ExceptionRuleSupplyChain, Path: ".github/workflows/release.yml", Category: "D", Reason: "release gap", Expires: "2026-12-01"}
	return []reconcileLintersCase{
		{name: "restored tool removes live entry", existing: []config.Exception{liveA}, today: today, wantChanged: true, wantValid: true},
		{name: "restored tool removes expired entry", existing: []config.Exception{expA}, today: today, wantChanged: true, wantValid: true},
		{name: "repeated live entries collapse to first", existing: []config.Exception{liveA, liveB}, missing: missing, today: today, want: []config.Exception{liveA}, wantChanged: true, wantValid: true},
		{name: "repeated expired entries collapse to first without renewal", existing: []config.Exception{expA, expB}, missing: missing, today: today, want: []config.Exception{expA}, wantChanged: true, wantExpired: []config.Exception{expA}, wantValid: true, wantAuditUnexcused: true},
		{name: "non-linter exception preserved beside expired linter entry", existing: []config.Exception{supply, expA}, missing: missing, today: today, want: []config.Exception{supply, expA}, wantExpired: []config.Exception{expA}, wantValid: true, wantAuditUnexcused: true},
	}
}

// TestAdopt_DeclaredLintersReAdoptKeepsExpiredEntry verifies through Adopt that plain and forced
// re-adoption preserve an expired declared-linters entry in .standards.yaml without minting a
// replacement, and that both AuditDeclaredLinters and config.ExpiredExceptions still fail on it.
func TestAdopt_DeclaredLintersReAdoptKeepsExpiredEntry(t *testing.T) {
	repoPath := newTestRepo(t, "readopt-keeps-expired")
	mustWrite(t, filepath.Join(repoPath, "main.go"), "package main\n\nfunc main() {}\n")

	source := newLintersLockSource(t)
	adoptWithSource(t, repoPath, source, false)
	initialCount := len(readDeclaredLinterExceptions(t, repoPath))
	yesterday := config.ExceptionDay(time.Now()).AddDate(0, 0, -1).Format(config.ExceptionDateLayout)
	wantExpired := expireManifestLinterException(t, repoPath, "gitleaks", "initial gitleaks waiver now expired", yesterday)

	adoptWithSource(t, repoPath, source, false)
	rep := adoptWithSource(t, repoPath, source, true)

	afterManifest, err := config.DecodeManifest([]byte(mustRead(t, filepath.Join(repoPath, manifestFile))))
	if err != nil {
		t.Fatalf("decode manifest after re-adoption: %v", err)
	}
	afterLinters := config.ExceptionsFor(afterManifest.Exceptions, config.ExceptionRuleDeclaredLinters)
	if len(afterLinters) != initialCount {
		t.Fatalf("re-adoption changed declared-linters count: got %d, want %d (%+v)", len(afterLinters), initialCount, afterLinters)
	}
	assertKeptExpiredLinterAndAuditFailure(t, repoPath, rep.EffectivePolicy, afterManifest.Exceptions, wantExpired)
}

// expireManifestLinterException rewrites the named declared-linters entry in repoPath's manifest
// to carry reason and expires, returning the written entry.
func expireManifestLinterException(t *testing.T, repoPath, tool, reason, expires string) config.Exception {
	t.Helper()
	full := filepath.Join(repoPath, manifestFile)
	raw := []byte(mustRead(t, full))
	manifest, err := config.DecodeManifest(raw)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	var updatedEntry config.Exception
	var found bool
	for i := 0; i < len(manifest.Exceptions) && i < config.MaxExceptions; i++ {
		if manifest.Exceptions[i].Rule == config.ExceptionRuleDeclaredLinters && manifest.Exceptions[i].Tool == tool {
			manifest.Exceptions[i].Reason = reason
			manifest.Exceptions[i].Expires = expires
			updatedEntry = manifest.Exceptions[i]
			found = true
		}
	}
	if !found {
		t.Fatalf("expected declared-linters entry for %s in fresh manifest", tool)
	}
	out, err := setManifestExceptions(t.Context(), raw, manifest.Exceptions)
	if err != nil {
		t.Fatalf("setManifestExceptions: %v", err)
	}
	mustWrite(t, full, string(out))
	return updatedEntry
}

// assertKeptExpiredLinterAndAuditFailure checks that exceptions still holds wantExpired verbatim
// and that both config.ExpiredExceptions and AuditDeclaredLinters fail on it.
func assertKeptExpiredLinterAndAuditFailure(t *testing.T, repoPath string, policy *config.EffectivePolicy, exceptions []config.Exception, wantExpired config.Exception) {
	t.Helper()
	today := time.Now()
	expired := config.ExpiredExceptions(exceptions, today)
	if !sameExceptions(expired, []config.Exception{wantExpired}) {
		t.Fatalf("ExpiredExceptions after re-adoption = %+v, want [%+v]", expired, wantExpired)
	}
	_, err := AuditDeclaredLinters(t.Context(), DeclaredLintersOptions{
		RootDir:    repoPath,
		Policy:     policy,
		Exceptions: exceptions,
		Today:      today,
	})
	if err == nil || !strings.Contains(err.Error(), wantExpired.Tool) || !strings.Contains(err.Error(), "expired on "+wantExpired.Expires) {
		t.Fatalf("AuditDeclaredLinters after re-adoption = %v, want expired failure for %s on %s", err, wantExpired.Tool, wantExpired.Expires)
	}
}
