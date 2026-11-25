package hisscoverage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cordanaLLM/praetor/internal/hisscatalog"
)

// recursiveGo is a Go source that HISS-01 reports.
const recursiveGo = "package p\n\nfunc F(n int) int {\n\tif n <= 1 {\n\t\treturn 1\n\t}\n\treturn n * F(n-1)\n}\n"

// cleanGo is a Go source that no invariant reports.
const cleanGo = "package p\n\nfunc F(n int) int { return n + 1 }\n"

// corpusRoot builds a fixture root and returns the repository root containing it.
func corpusRoot(t *testing.T, rule, lang, bucket, name, body string) string {
	t.Helper()
	root := t.TempDir()
	writeCorpusFixture(t, root, rule, lang, bucket, name, body)
	return root
}

// catalogFor builds a one-claim catalog.
func catalogFor(rule, lang string, state State) *Catalog {
	return &Catalog{Version: 1, Rules: []Rule{{
		ID:       rule,
		Coverage: []Coverage{{Language: lang, State: state, Mechanism: "internal/hiss", Rationale: "measured"}},
	}}}
}

// TestVerifyAcceptsABackedClaim is the positive dimension: a claim of detection whose
// positive fixture the rule actually reports must pass.
func TestVerifyAcceptsABackedClaim(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() {
		t.Fatalf("a backed claim must pass: %+v", report.Findings)
	}
	if report.Claims != 1 || report.Fixtures != 1 {
		t.Errorf("expected one claim over one fixture, got %d/%d", report.Claims, report.Fixtures)
	}
}

// TestVerifyRejectsAnUnmetClaim is the negative dimension and the defect this exists for: a
// rule declared as enforcing something it does not report is exactly the matrix cell that
// advertised a gate which did not exist.
func TestVerifyRejectsAnUnmetClaim(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "notrecursive.go", cleanGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("a claim of enforcement whose fixture is not reported must fail")
	}
	if !strings.Contains(report.Findings[0].Detail, "not reported") {
		t.Errorf("the finding must say the fixture went unreported: %s", report.Findings[0])
	}
}

// workflowOrTrue is a GitHub Actions workflow whose run: block discards a failure (HISS-07).
const workflowOrTrue = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make check || true\n"

// TestVerifyStagesWorkflowFixtures: a github-actions fixture is replayed from where GitHub reads
// workflows (hiss.FixturePath), so its run: block is scanned and the claim holds (positive).
// The same document replayed as a shell fixture is staged at the root, where it is an unread
// YAML file, so a claim backed by it fails (negative): the staging, not the bytes, decides.
func TestVerifyStagesWorkflowFixtures(t *testing.T) {
	root := corpusRoot(t, "HISS-07", "github-actions", bucketPositive, "or-true.yml", workflowOrTrue)
	report, err := Verify(t.Context(), root, catalogFor("HISS-07", "github-actions", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() || report.Fixtures != 1 {
		t.Fatalf("a workflow fixture must be staged where its run: block is read: %+v", report.Findings)
	}
	root = corpusRoot(t, "HISS-07", "shell", bucketPositive, "or-true.yml", workflowOrTrue)
	report, err = Verify(t.Context(), root, catalogFor("HISS-07", "shell", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("a workflow staged at the root is not a workflow, so the claim must fail")
	}
}

// TestVerifyRejectsOverMatching is the negative dimension for the other failure mode: a rule
// that reports legitimate code is as unusable as one that reports nothing, because it gets
// suppressed wholesale.
func TestVerifyRejectsOverMatching(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketNegative, "legitimate.go", recursiveGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("a negative fixture that is reported must fail")
	}
	if !strings.Contains(report.Findings[0].Detail, "over-matches") {
		t.Errorf("the finding must name over-matching: %s", report.Findings[0])
	}
}

// TestVerifyRejectsAClosedGap is the direction that keeps the catalog from going stale in
// the optimistic-looking direction. A fixture recorded as an undetected gap that starts
// being reported means the rule gained coverage, and the catalog must say so rather than
// continuing to understate what the gate does.
func TestVerifyRejectsAClosedGap(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketGap, "nowdetected.go", recursiveGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("a gap fixture that is now reported must fail so the catalog is updated")
	}
	if !strings.Contains(report.Findings[0].Detail, "close the gap") {
		t.Errorf("the finding must direct the reader to close the gap: %s", report.Findings[0])
	}
}

// TestVerifyRejectsUndeclaredCoverage is the same direction for a state that claims no
// enforcement at all: an unsupported rule whose positive fixture fires is understating the
// gate, which matters because an unsupported state is used to justify not relying on it.
func TestVerifyRejectsUndeclaredCoverage(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateUnsupported))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() {
		t.Fatal("an unsupported claim whose fixture is reported must fail")
	}
	if !strings.Contains(report.Findings[0].Detail, "understates coverage") {
		t.Errorf("the finding must name the understatement: %s", report.Findings[0])
	}
}

// TestVerifyReportsAnUnbackedClaim is the boundary dimension between wrong and
// undemonstrated: a claim with no fixture at all is not contradicted, but it is not
// evidence either, so it is surfaced without failing the gate while the corpus is filled in.
func TestVerifyReportsAnUnbackedClaim(t *testing.T) {
	report, err := Verify(t.Context(), t.TempDir(), catalogFor("HISS-01", "go", StateEnforced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() {
		t.Errorf("an unbacked claim is undemonstrated, not contradicted: %+v", report.Findings)
	}
	if len(report.Unbacked) != 1 {
		t.Fatalf("an unbacked claim must be surfaced, got %v", report.Unbacked)
	}
}

// TestValidateRefusesDetectionWithoutMechanism is the boundary dimension on the catalog
// itself. A claim of enforcement with no named mechanism is precisely how a cell comes to
// advertise a gate that does not exist, so it is refused at load rather than verified.
func TestValidateRefusesDetectionWithoutMechanism(t *testing.T) {
	catalog := catalogFor("HISS-01", "go", StateEnforced)
	catalog.Rules[0].Coverage[0].Mechanism = "  "

	err := catalog.Validate()
	if !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("expected an invalid-catalog error, got %v", err)
	}
	if !strings.Contains(err.Error(), "mechanism") {
		t.Errorf("the error must name the missing mechanism: %v", err)
	}
}

// TestValidateRefusesUnknownState is the negative dimension for the state vocabulary: an
// unrecognised state must be an error, because silently ignoring it would read as coverage.
func TestValidateRefusesUnknownState(t *testing.T) {
	catalog := catalogFor("HISS-01", "go", State("mostly"))

	if err := catalog.Validate(); !errors.Is(err, ErrUnknownState) {
		t.Fatalf("expected an unknown-state error, got %v", err)
	}
}

// TestValidateRefusesDuplicateAndEmpty is the boundary dimension for catalog identity: a
// rule declared twice, or a language declared twice within a rule, makes the effective claim
// depend on ordering.
func TestValidateRefusesDuplicateAndEmpty(t *testing.T) {
	empty := &Catalog{Version: 1}
	if err := empty.Validate(); !errors.Is(err, ErrInvalidCatalog) {
		t.Errorf("a catalog with no rules must be refused, got %v", err)
	}

	dupRule := catalogFor("HISS-01", "go", StatePartial)
	dupRule.Rules = append(dupRule.Rules, dupRule.Rules[0])
	if err := dupRule.Validate(); !errors.Is(err, ErrInvalidCatalog) {
		t.Errorf("a rule declared twice must be refused, got %v", err)
	}

	dupLang := catalogFor("HISS-01", "go", StatePartial)
	dupLang.Rules[0].Coverage = append(dupLang.Rules[0].Coverage, dupLang.Rules[0].Coverage[0])
	if err := dupLang.Validate(); !errors.Is(err, ErrInvalidCatalog) {
		t.Errorf("a language declared twice must be refused, got %v", err)
	}
}

// TestLoadCatalogAbsent is the boundary dimension for a repository that declares nothing:
// absence is reported as its own condition rather than as an empty, passing catalog.
func TestLoadCatalogAbsent(t *testing.T) {
	if _, err := LoadCatalog(t.Context(), t.TempDir()); !errors.Is(err, ErrCatalogAbsent) {
		t.Fatalf("expected ErrCatalogAbsent, got %v", err)
	}
}

// TestLoadCatalogRejectsUnknownField is the negative dimension for the catalog document: a
// misspelled key must fail rather than silently dropping a claim.
func TestLoadCatalogRejectsUnknownField(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".config", "hiss")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	body := "version: 1\nrules:\n  - id: HISS-01\n    title: t\n    covrage:\n      - language: go\n"
	if err := os.WriteFile(filepath.Join(dir, "coverage.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	if _, err := LoadCatalog(t.Context(), root); err == nil {
		t.Fatal("a misspelled catalog key must be refused")
	}
}

// TestRepositoryCatalogVerifies is the boundary dimension against the real artifact: this
// repository's own catalog must load and every claim must survive its fixtures, which is
// what makes the committed file evidence rather than documentation.
func TestRepositoryCatalogVerifies(t *testing.T) {
	root := filepath.Join("..", "..")
	catalog, err := LoadCatalog(t.Context(), root)
	if err != nil {
		t.Fatalf("the repository catalog must load: %v", err)
	}
	report, err := Verify(t.Context(), root, catalog)
	if err != nil {
		t.Fatalf("verify repository catalog: %v", err)
	}
	if !report.Passed() {
		t.Fatalf("every declared claim must hold: %+v", report.Findings)
	}
	if report.Fixtures == 0 {
		t.Error("the repository catalog must be backed by at least one fixture")
	}
}

// branchyGo returns a Go function of cyclomatic complexity n built from n-1 flat ifs, padded
// with pad extra lines so the length rule can be made to fire as well.
func branchyGo(n, pad int) string {
	var sb strings.Builder
	sb.WriteString("package p\n\nfunc F(x int) int {\n")
	for i := 1; i < n; i++ {
		sb.WriteString("\tif x > 0 {\n\t\tx++\n\t}\n")
	}
	sb.WriteString(strings.Repeat("\t// padding\n", pad))
	sb.WriteString("\treturn x\n}\n")
	return sb.String()
}

// verifyHISS04 replays one fixture of a partial HISS-04/go claim and returns the findings.
func verifyHISS04(t *testing.T, bucket, body string) []Finding {
	t.Helper()
	root := corpusRoot(t, "HISS-04", "go", bucket, "fixture.go", body)
	writeLOCPositive(t, root)
	report, err := Verify(t.Context(), root, catalogFor("HISS-04", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return report.Findings
}

// writeLOCPositive backs the partial claim with a length violation, so only the fixture under
// test can produce a finding.
func writeLOCPositive(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(FixtureDir), "HISS-04", "go", bucketPositive)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "long.go"), []byte(branchyGo(1, 70)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Positive: a measured fixture that yields a measurement and no violation holds; so does a
// negative fixture sitting exactly at the limit.
func TestVerifyAcceptsAMeasuredFixture(t *testing.T) {
	if findings := verifyHISS04(t, bucketMeasured, branchyGo(11, 0)); len(findings) != 0 {
		t.Errorf("a measured fixture over the limit must hold: %+v", findings)
	}
	if findings := verifyHISS04(t, bucketNegative, branchyGo(10, 0)); len(findings) != 0 {
		t.Errorf("a negative fixture at the limit must hold: %+v", findings)
	}
}

// Negative, both directions: a measured fixture that yields no measurement fails, and a
// negative fixture one over the limit fails because the measurement over-matches.
func TestVerifyRejectsAMissingOrOverMatchingMeasurement(t *testing.T) {
	for _, tc := range []struct {
		bucket, body, detail string
	}{
		{bucketMeasured, branchyGo(10, 0), "yields no measurement"},
		{bucketNegative, branchyGo(11, 0), "measured over a limit"},
	} {
		findings := verifyHISS04(t, tc.bucket, tc.body)
		if len(findings) != 1 || !strings.Contains(findings[0].Detail, tc.detail) {
			t.Errorf("%s fixture: findings %+v, want one saying %q", tc.bucket, findings, tc.detail)
		}
	}
}

// Boundary: a measured fixture that is also a violation fails, because a measurement must
// never be what enforces a shape.
func TestVerifyRejectsAMeasuredFixtureThatIsEnforced(t *testing.T) {
	findings := verifyHISS04(t, bucketMeasured, branchyGo(11, 40))
	if len(findings) != 1 || !strings.Contains(findings[0].Detail, "never be enforced") {
		t.Errorf("findings %+v, want the enforced measured fixture", findings)
	}
}

// TestValidateRefusesUnregisteredRule: coverage evidence for an identifier the HISS catalog
// does not define describes enforcement of nothing any other surface names. Positive: the
// last catalog rule validates. Negative: the next identifier is refused.
func TestValidateRefusesUnregisteredRule(t *testing.T) {
	if err := catalogFor("HISS-21", "go", StateManual).Validate(); err != nil {
		t.Fatalf("the last catalog invariant must validate: %v", err)
	}
	err := catalogFor("HISS-22", "go", StateManual).Validate()
	if !errors.Is(err, ErrInvalidCatalog) || !strings.Contains(err.Error(), "not a registered invariant") {
		t.Fatalf("an unregistered rule must be refused, got %v", err)
	}
}

// titledCatalog is catalogFor with a declared title on its one rule.
func titledCatalog(rule, title string) *Catalog {
	catalog := catalogFor(rule, "go", StateManual)
	catalog.Rules[0].Title = title
	return catalog
}

// TestValidateTitleDefersToTheHISSCatalog: a rule's name lives in the HISS catalog, so a
// coverage entry may omit its title or repeat the catalog's, never state another. Positive: an
// omitted title and the catalog's own title validate, and CatalogTitle reads the catalog.
func TestValidateTitleDefersToTheHISSCatalog(t *testing.T) {
	registered, ok := hisscatalog.LookupRule("HISS-14")
	if !ok {
		t.Fatal("HISS-14 missing from the HISS catalog")
	}
	for _, title := range []string{"", registered.Title} {
		catalog := titledCatalog("HISS-14", title)
		if err := catalog.Validate(); err != nil {
			t.Fatalf("title %q must validate: %v", title, err)
		}
		if got := catalog.Rules[0].CatalogTitle(); got != registered.Title {
			t.Fatalf("CatalogTitle() = %q, want the catalog's %q", got, registered.Title)
		}
	}
}

// Negative: a title the catalog does not state, such as the shortened name coverage.yaml
// carried before the catalog was the one list ("Append-Only ABI"), is a warning naming the
// catalog's current text, never a failure: the catalog owns the titles, and a retitle there
// must not break a coverage file that repeats the earlier text (#844). CatalogTitle still
// reads the catalog.
func TestValidateWarnsOnADriftedTitle(t *testing.T) {
	registered, _ := hisscatalog.LookupRule("HISS-14")
	catalog := titledCatalog("HISS-14", "Append-Only ABI")
	if err := catalog.Validate(); err != nil {
		t.Fatalf("a drifted title must not fail validation: %v", err)
	}
	stale := catalog.StaleTitles()
	want := StaleTitle{ID: "HISS-14", Declared: "Append-Only ABI", Catalog: registered.Title}
	if len(stale) != 1 || stale[0] != want {
		t.Fatalf("StaleTitles() = %+v, want [%+v]", stale, want)
	}
	if !strings.Contains(stale[0].String(), `the HISS catalog title "`+registered.Title+`"`) {
		t.Fatalf("the warning must name the catalog's text: %s", stale[0])
	}
	if got := catalog.Rules[0].CatalogTitle(); got != registered.Title {
		t.Fatalf("CatalogTitle() = %q, want the catalog's %q", got, registered.Title)
	}
}

// Boundary: the comparison is exact. A title differing from the catalog's only in case or by
// surrounding whitespace is still a second spelling and is reported; an omitted title or the
// catalog's own is not; an unregistered identifier is still refused for the identifier, and
// CatalogTitle falls back to the declared title.
func TestValidateTitleComparisonIsExact(t *testing.T) {
	registered, _ := hisscatalog.LookupRule("HISS-01")
	for _, title := range []string{strings.ToLower(registered.Title), " " + registered.Title} {
		catalog := titledCatalog("HISS-01", title)
		if err := catalog.Validate(); err != nil {
			t.Errorf("title %q must validate, got %v", title, err)
		}
		if stale := catalog.StaleTitles(); len(stale) != 1 || stale[0].Declared != title {
			t.Errorf("title %q must be reported stale, got %+v", title, stale)
		}
	}
	for _, title := range []string{"", registered.Title} {
		if stale := titledCatalog("HISS-01", title).StaleTitles(); len(stale) != 0 {
			t.Errorf("title %q must not be reported stale, got %+v", title, stale)
		}
	}
	unknown := titledCatalog("HISS-22", "Declared Only")
	if stale := unknown.StaleTitles(); len(stale) != 0 {
		t.Errorf("an unregistered rule is refused by Validate, not reported stale: %+v", stale)
	}
	if err := unknown.Validate(); err == nil || !strings.Contains(err.Error(), "not a registered invariant") {
		t.Fatalf("unregistered rule must be refused for its identifier, got %v", err)
	}
	if got := unknown.Rules[0].CatalogTitle(); got != "Declared Only" {
		t.Fatalf("CatalogTitle() of an unregistered rule = %q, want the declared title", got)
	}
}

// malformedGo is an unparseable Go file: go/parser reports EOF inside the open function body.
const malformedGo = "package p\n\nfunc F() {\n"

// writeCorpusFixture stages an additional fixture file under an existing corpus root.
func writeCorpusFixture(t *testing.T, root, rule, lang, bucket, name, body string) {
	t.Helper()
	plantCorpusFile(t, root, rule+"/"+lang+"/"+bucket+"/"+name, body)
}

// delegatedCatalogFor builds a one-claim catalog attributed to runner.
func delegatedCatalogFor(rule, lang, runner string) *Catalog {
	catalog := catalogFor(rule, lang, StatePartial)
	catalog.Rules[0].Coverage[0].Runner = runner
	catalog.Rules[0].Coverage[0].Mechanism = runner
	return catalog
}

// requireFinding asserts Verify rejects root against catalog with one finding naming fixture and detail.
func requireFinding(t *testing.T, label, root string, catalog *Catalog, fixture, detail string) {
	t.Helper()
	report, err := Verify(t.Context(), root, catalog)
	if err != nil {
		t.Fatalf("%s: verify error: %v", label, err)
	}
	if report.Passed() {
		t.Fatalf("%s: non-certifying fixture %s passed silently", label, fixture)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("%s: findings = %+v, want 1", label, report.Findings)
	}
	got := report.Findings[0]
	if got.Fixture != fixture || !strings.Contains(got.Detail, detail) {
		t.Errorf("%s: finding = %q, want fixture %q containing %q", label, got, fixture, detail)
	}
}

// TestVerifyAcceptsCleanNegativeControl is the control case that holds before and after E01:
// a valid, fully parsed negative Go fixture passes with zero findings on both a HISS-replayed
// claim and a delegated claim.
func TestVerifyAcceptsCleanNegativeControl(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "clean.go", cleanGo)
	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil || !report.Passed() {
		t.Fatalf("clean HISS negative control must pass: err=%v findings=%+v", err, report.Findings)
	}

	delegated := corpusRoot(t, "HISS-10", "go", bucketNegative, "clean.go", cleanGo)
	report, err = Verify(t.Context(), delegated, delegatedCatalogFor("HISS-10", "go", "golangci-lint"))
	if err != nil || !report.Passed() {
		t.Fatalf("clean delegated negative control must pass: err=%v findings=%+v", err, report.Findings)
	}
}

// TestVerifyRejectsMalformedNegativeFixture pins E01's primary defect: a malformed negative Go
// fixture yields zero infractions only because go/parser could not parse its body, so it must
// fail naming the fixture and the unparsed reason rather than certifying non-overmatching.
func TestVerifyRejectsMalformedNegativeFixture(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "malformed.go", malformedGo)
	requireFinding(t, "malformed negative", root, catalogFor("HISS-01", "go", StatePartial),
		"malformed.go", "no analyzable structure")
}

// TestVerifyRejectsMalformedGapAndDelegatedFixtures verifies that unmarked unparsed Go fixtures
// fail in gap/ and in delegated buckets too, rather than certifying absence or attribution.
func TestVerifyRejectsMalformedGapAndDelegatedFixtures(t *testing.T) {
	gapRoot := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, gapRoot, "HISS-01", "go", bucketGap, "malformed-gap.go", malformedGo)
	requireFinding(t, "malformed gap", gapRoot, catalogFor("HISS-01", "go", StatePartial),
		"malformed-gap.go", "no analyzable structure")

	delRoot := corpusRoot(t, "HISS-10", "go", bucketNegative, "malformed-delegated.go", malformedGo)
	requireFinding(t, "malformed delegated", delRoot, delegatedCatalogFor("HISS-10", "go", "golangci-lint"),
		"malformed-delegated.go", "no analyzable structure")
}

// TestVerifyRejectsTruncatedFixtureScan drives hiss.Scan's AST-depth truncation path and
// verifies that a truncated negative, gap or delegated scan fails naming the fixture and reason.
func TestVerifyRejectsTruncatedFixtureScan(t *testing.T) {
	deepGo := "package p\n\nfunc F() int { return " + strings.Repeat("(", 1030) + "1" + strings.Repeat(")", 1030) + " }\n"
	buckets := [...]string{bucketNegative, bucketGap}
	for i := 0; i < len(buckets); i++ {
		root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
		writeCorpusFixture(t, root, "HISS-01", "go", buckets[i], "deep.go", deepGo)
		requireFinding(t, "truncated "+buckets[i], root, catalogFor("HISS-01", "go", StatePartial),
			"deep.go", "truncated")
	}

	delRoot := corpusRoot(t, "HISS-10", "go", bucketNegative, "deep.go", deepGo)
	requireFinding(t, "truncated delegated", delRoot, delegatedCatalogFor("HISS-10", "go", "golangci-lint"),
		"deep.go", "truncated")
}

// TestVerifyRejectsZeroFileFixtureScan verifies that zero examined files for the claim's
// language fail negative, gap and delegated claims, including a language with no HISS scanner.
func TestVerifyRejectsZeroFileFixtureScan(t *testing.T) {
	negJava := corpusRoot(t, "HISS-01", "java", bucketNegative, "Clean.java", "class Clean {}\n")
	requireFinding(t, "scannerless negative", negJava, catalogFor("HISS-01", "java", StateUnsupported),
		"Clean.java", "no HISS scanner reads java")

	gapJava := corpusRoot(t, "HISS-01", "java", bucketGap, "Loop.java", "class Loop { void f() { while (true) {} } }\n")
	requireFinding(t, "scannerless gap", gapJava, catalogFor("HISS-01", "java", StateUnsupported),
		"Loop.java", "no HISS scanner reads java")

	delGo := corpusRoot(t, "HISS-10", "go", bucketNegative, "notes.txt", "not Go source\n")
	requireFinding(t, "zero-file delegated go", delGo, delegatedCatalogFor("HISS-10", "go", "golangci-lint"),
		"notes.txt", "examined no go file")
}

// markedUnparsedGo is an intentional parser-failure gap fixture carrying a hiss-fixture header.
const markedUnparsedGo = "// hiss-fixture: unparsed: partial syntax recovery gap\npackage p\n\nfunc F() {\n"

// markedCleanGo carries an unparsed marker over valid Go source, which must fail as stale.
const markedCleanGo = "// hiss-fixture: unparsed: partial syntax recovery gap\npackage p\n\nfunc F(n int) int { return n + 1 }\n"

// markedReasonlessGo carries an unparsed marker with no reason, which must be refused.
const markedReasonlessGo = "// hiss-fixture: unparsed:\npackage p\n\nfunc F() {\n"

// TestVerifyIntentionalGapMarkerContract verifies that an intentional parser-failure gap stays
// representable in gap/ with a reason, fails when it parses cleanly, and is refused in negative/.
func TestVerifyIntentionalGapMarkerContract(t *testing.T) {
	validGap := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, validGap, "HISS-01", "go", bucketGap, "partial.go", markedUnparsedGo)
	if report, err := Verify(t.Context(), validGap, catalogFor("HISS-01", "go", StatePartial)); err != nil || !report.Passed() {
		t.Fatalf("marked unparsed gap must hold while unparseable: err=%v findings=%+v", err, report.Findings)
	}

	staleGap := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, staleGap, "HISS-01", "go", bucketGap, "clean.go", markedCleanGo)
	requireFinding(t, "stale unparsed marker", staleGap, catalogFor("HISS-01", "go", StatePartial),
		"clean.go", "marked unparsed")

	negMarked := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, negMarked, "HISS-01", "go", bucketNegative, "marked.go", markedUnparsedGo)
	requireFinding(t, "negative with marker", negMarked, catalogFor("HISS-01", "go", StatePartial),
		"marked.go", "only valid in gap/")

	noReason := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	writeCorpusFixture(t, noReason, "HISS-01", "go", bucketGap, "no-reason.go", markedReasonlessGo)
	requireFinding(t, "marker without reason", noReason, catalogFor("HISS-01", "go", StatePartial),
		"no-reason.go", "reason")
}

// plantCorpusFile writes body at rel (a slash path below FixtureDir) inside root.
func plantCorpusFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	slashRel := FixtureDir + "/" + rel
	full := filepath.Join(root, filepath.FromSlash(slashRel))
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create dir for %s: %v", slashRel, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", slashRel, err)
	}
	return slashRel
}

// withoutCoverageCell returns a shallow copy of catalog with ruleID/lang removed, and reports
// whether the cell was present.
func withoutCoverageCell(catalog *Catalog, ruleID, lang string) (*Catalog, bool) {
	out := &Catalog{Version: catalog.Version, Rules: make([]Rule, 0, len(catalog.Rules))}
	removed := false
	for i := 0; i < len(catalog.Rules); i++ {
		rule := catalog.Rules[i]
		if rule.ID != ruleID {
			out.Rules = append(out.Rules, rule)
			continue
		}
		kept := make([]Coverage, 0, len(rule.Coverage))
		for j := 0; j < len(rule.Coverage); j++ {
			if rule.Coverage[j].Language == lang {
				removed = true
				continue
			}
			kept = append(kept, rule.Coverage[j])
		}
		rule.Coverage = kept
		if len(rule.Coverage) > 0 {
			out.Rules = append(out.Rules, rule)
		}
	}
	return out, removed
}

// TestVerifyCorpusOwnershipControl is the passing control case that holds before and after
// corpus-ownership reconciliation: fixtures inside valid buckets of declared cells pass Verify.
func TestVerifyCorpusOwnershipControl(t *testing.T) {
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	plantCorpusFile(t, root, "HISS-01/go/gap/method-cycle.go", cleanGo)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Passed() || report.Fixtures != 2 {
		t.Fatalf("owned positive and gap fixtures must pass (fixtures=%d): %+v", report.Fixtures, report.Findings)
	}
}

// TestVerifyCommittedCorpusOwnsHISS08Rust verifies that the committed catalog owns HISS-08/rust
// as unsupported with mechanism none and that the whole committed fixture corpus passes Verify.
func TestVerifyCommittedCorpusOwnsHISS08Rust(t *testing.T) {
	root := filepath.Join("..", "..")
	catalog, err := LoadCatalog(t.Context(), root)
	if err != nil {
		t.Fatalf("load repository catalog: %v", err)
	}
	cov, ok := catalog.Lookup("HISS-08", "rust")
	if !ok {
		t.Fatalf("HISS-08/rust must be declared in %s so its gap fixtures have an owner", CatalogFile)
	}
	if cov.State != StateUnsupported || cov.Mechanism != "none" || !cov.ReplayedHere() {
		t.Fatalf("HISS-08/rust = %+v, want state=%q mechanism=%q replayed directly", cov, StateUnsupported, "none")
	}
	report, err := Verify(t.Context(), root, catalog)
	if err != nil {
		t.Fatalf("verify repository catalog: %v", err)
	}
	if !report.Passed() {
		t.Fatalf("committed corpus must pass Verify: %+v", report.Findings)
	}
}

// TestVerifyRejectsOrphanFixtures is the negative dimension for corpus ownership: any fixture
// file under FixtureDir that maps to no declared rule/language cell or valid bucket fails Verify
// and names the path.
func TestVerifyRejectsOrphanFixtures(t *testing.T) {
	cases := []struct {
		name string
		rel  string
	}{
		{"undeclared rule and language", "HISS-08/rust/gap/orphan.rs"},
		{"corpus root file", "orphan.go"},
		{"rule level file", "HISS-01/orphan.go"},
		{"language level file outside bucket", "HISS-01/go/orphan.go"},
		{"unknown bucket", "HISS-01/go/retired/orphan.go"},
		{"nested subdirectory inside bucket", "HISS-01/go/positive/nested/orphan.go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
			wantPath := plantCorpusFile(t, root, tc.rel, cleanGo)
			report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if report.Passed() {
				t.Fatalf("planted orphan %s passed Verify", wantPath)
			}
			if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].String(), wantPath) {
				t.Fatalf("findings = %+v, want one naming %s", report.Findings, wantPath)
			}
		})
	}
}

// TestVerifyRejectsMisspelledLanguageDirectory is the negative and boundary dimension for
// directory ownership: a misspelled language directory or undeclared rule directory fails Verify
// whether it holds fixtures or sits empty on disk, naming its path.
func TestVerifyRejectsMisspelledLanguageDirectory(t *testing.T) {
	t.Run("populated misspelled language", func(t *testing.T) {
		root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
		wantPath := plantCorpusFile(t, root, "HISS-01/golnag/positive/recursion.go", recursiveGo)
		report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if report.Passed() || len(report.Findings) != 1 || !strings.Contains(report.Findings[0].String(), wantPath) {
			t.Fatalf("findings = %+v, want failure naming %s", report.Findings, wantPath)
		}
	})
	for _, rel := range []string{"HISS-01/golnag", "HISS-03"} {
		t.Run("empty "+rel, func(t *testing.T) {
			root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
			wantPath := FixtureDir + "/" + rel
			// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- an empty directory fixture needs the owner execute bit to be listed; 0o750 matches the fixture tree
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(wantPath)), 0o750); err != nil {
				t.Fatalf("mkdir %s: %v", wantPath, err)
			}
			report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if report.Passed() || len(report.Findings) != 1 || !strings.Contains(report.Findings[0].String(), wantPath) {
				t.Fatalf("findings = %+v, want failure naming %s", report.Findings, wantPath)
			}
		})
	}
}

// TestVerifyRemovingHISS08RustFailsCommittedCorpus proves the three committed HISS-08 Rust gap
// fixtures are owned by HISS-08/rust: dropping that cell makes Verify fail and name all three.
func TestVerifyRemovingHISS08RustFailsCommittedCorpus(t *testing.T) {
	root := filepath.Join("..", "..")
	catalog, err := LoadCatalog(t.Context(), root)
	if err != nil {
		t.Fatalf("load repository catalog: %v", err)
	}
	trimmed, removed := withoutCoverageCell(catalog, "HISS-08", "rust")
	if !removed {
		t.Errorf("HISS-08/rust must be declared in %s", CatalogFile)
	}
	report, err := Verify(t.Context(), root, trimmed)
	if err != nil {
		t.Fatalf("verify without HISS-08/rust: %v", err)
	}
	if report.Passed() {
		t.Fatal("without HISS-08/rust, the committed Rust gap fixtures are unowned and Verify must fail")
	}
	want := []string{
		".config/hiss/testdata/HISS-08/rust/gap/command-shell.rs",
		".config/hiss/testdata/HISS-08/rust/gap/libc-kill.rs",
		".config/hiss/testdata/HISS-08/rust/gap/libloading-open.rs",
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("findings = %+v, want the %d HISS-08/rust gap files", report.Findings, len(want))
	}
	for i := range want {
		if !strings.Contains(report.Findings[i].String(), want[i]) {
			t.Errorf("finding %d = %q, want path %s", i, report.Findings[i], want[i])
		}
	}
}

// plantSymlink creates a symbolic link at linkPath pointing to target, skipping on hosts without symlink rights.
func plantSymlink(t *testing.T, target, linkPath string) {
	t.Helper()
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- parent fixture directories require the owner execute bit to be traversed
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o750); err != nil {
		t.Fatalf("mkdir parent for %s: %v", linkPath, err)
	}
	if err := os.Symlink(target, linkPath); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
}

// TestVerifyRejectsSymlinkedCorpusRoot verifies that a corpus root symlink to a directory outside
// the repository (or a path escaping rootDir via "..") fails Verify naming the path and lists
// nothing from outside.
func TestVerifyRejectsSymlinkedCorpusRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside-secret.go"), []byte(cleanGo), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	root := t.TempDir()
	corpusPath := filepath.Join(root, filepath.FromSlash(FixtureDir))
	plantSymlink(t, outside, corpusPath)

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StateUnsupported))
	if err == nil {
		t.Fatalf("symlinked corpus root must fail Verify, got report=%+v", report)
	}
	if !strings.Contains(err.Error(), corpusPath) && !strings.Contains(err.Error(), FixtureDir) {
		t.Errorf("error = %q, want corpus path %s", err, corpusPath)
	}
	if strings.Contains(err.Error(), "outside-secret.go") || report != nil {
		t.Errorf("Verify leaked outside entries: report=%+v err=%v", report, err)
	}

	escapeRoot := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	if _, err := Verify(t.Context(), escapeRoot, catalogFor("HISS-01", "../../../../outside", StateManual)); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escaping language path error = %v, want escapes repository root", err)
	}
}

// TestVerifyRejectsSymlinkedDirectoryInsideCorpus verifies that a symlinked directory anywhere
// inside FixtureDir is reported as an unowned symlink and never entered.
func TestVerifyRejectsSymlinkedDirectoryInsideCorpus(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside-leak.go"), []byte(recursiveGo), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	rels := []string{
		"HISS-01/go/gap",
		"HISS-01/rust",
		"HISS-01/golnag/linked",
		"HISS-01/go/positive/nested/linked",
	}
	for i := 0; i < len(rels); i++ {
		rel := rels[i]
		t.Run(rel, func(t *testing.T) {
			assertSymlinkedCorpusSubdirNotEntered(t, outside, rel)
		})
	}
}

// assertSymlinkedCorpusSubdirNotEntered plants a symlink to outside at FixtureDir/rel and checks
// that Verify reports the symlink path without replaying or listing anything inside outside.
func assertSymlinkedCorpusSubdirNotEntered(t *testing.T, outside, rel string) {
	t.Helper()
	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	wantRel := FixtureDir + "/" + rel
	plantSymlink(t, outside, filepath.Join(root, filepath.FromSlash(wantRel)))

	report, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Passed() || report.Fixtures != 1 {
		t.Fatalf("symlink %s must fail without replaying outside files: fixtures=%d findings=%+v",
			wantRel, report.Fixtures, report.Findings)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].String(), wantRel) {
		t.Fatalf("findings = %+v, want one naming %s", report.Findings, wantRel)
	}
	if strings.Contains(report.Findings[0].String(), "outside-leak.go") {
		t.Fatalf("finding leaked target contents: %s", report.Findings[0])
	}
}

// corpusDirOpener is satisfied when corpusChecker streams directories through an injectable opener.
type corpusDirOpener interface {
	setOpenDir(func(string) (fs.ReadDirFile, error))
}

// installCorpusDirOpener attaches open when v supports chunked directory streaming.
func installCorpusDirOpener(v any, open func(string) (fs.ReadDirFile, error)) bool {
	cfg, ok := v.(corpusDirOpener)
	if ok {
		cfg.setOpenDir(open)
	}
	return ok
}

// syntheticDirEntry implements fs.DirEntry for bounded directory-reader tests.
type syntheticDirEntry struct {
	name string
}

// Name returns the synthetic entry's filename.
func (e syntheticDirEntry) Name() string { return e.name }

// IsDir reports false because synthetic entries represent regular files.
func (e syntheticDirEntry) IsDir() bool { return false }

// Type returns regular-file mode bits.
func (e syntheticDirEntry) Type() fs.FileMode { return 0 }

// Info returns os.ErrNotExist; readDirBounded inspects Name only while reading chunks.
func (e syntheticDirEntry) Info() (fs.FileInfo, error) { return nil, os.ErrNotExist }

// countingSyntheticDir yields total synthetic entries across ReadDir(n) calls while recording
// the total entries handed back to the caller.
type countingSyntheticDir struct {
	info     fs.FileInfo
	total    int
	offset   int
	returned *int
}

// Stat returns the real directory's FileInfo so handle identity validation passes.
func (d *countingSyntheticDir) Stat() (fs.FileInfo, error) { return d.info, nil }

// Read returns io.EOF on directory streams.
func (d *countingSyntheticDir) Read([]byte) (int, error) { return 0, io.EOF }

// Close satisfies fs.File.
func (d *countingSyntheticDir) Close() error { return nil }

// ReadDir returns up to n synthetic entries (or all remaining when n <= 0) and counts them.
func (d *countingSyntheticDir) ReadDir(n int) ([]fs.DirEntry, error) {
	rem := d.total - d.offset
	if rem <= 0 {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	take := rem
	if n > 0 && n < take {
		take = n
	}
	out := make([]fs.DirEntry, take)
	for i := 0; i < take; i++ {
		out[i] = syntheticDirEntry{name: fmt.Sprintf("entry-%05d.go", d.offset+i)}
	}
	d.offset += take
	*d.returned += take
	return out, nil
}

// TestVerifyCorpusDirectoryEntryBound verifies that maxCorpusEntries+1 fails with the bound error
// and that the chunked reader pulls at most maxCorpusEntries plus one chunk from an oversized dir.
func TestVerifyCorpusDirectoryEntryBound(t *testing.T) {
	const oneChunk = 256
	assertSyntheticCorpusEntryBound(t, maxCorpusEntries+1, maxCorpusEntries+oneChunk)
	assertSyntheticCorpusEntryBound(t, maxCorpusEntries*2, maxCorpusEntries+oneChunk)

	root := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	overDir := filepath.Join(root, filepath.FromSlash(FixtureDir), "HISS-01", "golnag")
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- fixture directory needs the owner execute bit to be listed
	if err := os.MkdirAll(overDir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", overDir, err)
	}
	for i := 0; i < maxCorpusEntries+1; i++ {
		name := filepath.Join(overDir, fmt.Sprintf("f%04d.go", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if _, err := Verify(t.Context(), root, catalogFor("HISS-01", "go", StatePartial)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Verify over %d entries = %v, want bound error", maxCorpusEntries+1, err)
	}
}

// assertSyntheticCorpusEntryBound checks readDirBounded against total synthetic entries and verifies
// the reader returned between maxCorpusEntries+1 and maxAllowed entries.
func assertSyntheticCorpusEntryBound(t *testing.T, total, maxAllowed int) {
	t.Helper()
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("lstat %s: %v", dir, err)
	}
	returned := 0
	checker := newCorpusChecker(catalogFor("HISS-01", "go", StatePartial), &Report{})
	installed := installCorpusDirOpener(checker, func(string) (fs.ReadDirFile, error) {
		return &countingSyntheticDir{info: info, total: total, returned: &returned}, nil
	})
	if !installed {
		t.Fatalf("readDirBounded does not stream directory entries in bounded chunks")
	}
	_, err = checker.readDirBounded(t.Context(), dir)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readDirBounded(%d entries) error = %v, want bound error", total, err)
	}
	if returned < maxCorpusEntries+1 || returned > maxAllowed {
		t.Fatalf("reader returned %d entries for total=%d, want [%d, %d]",
			returned, total, maxCorpusEntries+1, maxAllowed)
	}
}

// cancelAfterErrCallsContext cancels its underlying context on Err call number limit so a multi-chunk
// directory read sees cancellation between chunks deterministically.
type cancelAfterErrCallsContext struct {
	context.Context
	cancel context.CancelFunc
	calls  atomic.Int64
	limit  int64
}

// Err returns nil through call limit (cancelling on call limit) and the cancelled error thereafter.
func (c *cancelAfterErrCallsContext) Err() error {
	n := c.calls.Add(1)
	if n < c.limit {
		return nil
	}
	if n == c.limit {
		c.cancel()
		return nil
	}
	return c.Context.Err()
}

// TestVerifyCancelledContextStopsCorpusWalk verifies that both a pre-cancelled context and a
// context cancelled between ReadDir chunks stop Verify with the context error.
func TestVerifyCancelledContextStopsCorpusWalk(t *testing.T) {
	preRoot := t.TempDir()
	plantCorpusFile(t, preRoot, "orphan.go", cleanGo)
	preCtx, preCancel := context.WithCancel(t.Context())
	preCancel()
	if _, err := Verify(preCtx, preRoot, catalogFor("HISS-01", "go", StateUnsupported)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Verify error = %v, want context.Canceled", err)
	}

	midRoot := t.TempDir()
	for i := 0; i < 300; i++ {
		plantCorpusFile(t, midRoot, fmt.Sprintf("orphan-%03d.go", i), cleanGo)
	}
	inner, cancel := context.WithCancel(t.Context())
	defer cancel()
	midCtx := &cancelAfterErrCallsContext{Context: inner, cancel: cancel, limit: 1}
	if _, err := Verify(midCtx, midRoot, catalogFor("HISS-01", "go", StateUnsupported)); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancelled Verify error = %v, want context.Canceled", err)
	}
}

// TestVerifyBoundsUnownedSubtreeFindings verifies that an unowned subtree with more files than the
// per-subtree findings cap yields the cap plus one summary finding naming the omitted file count.
func TestVerifyBoundsUnownedSubtreeFindings(t *testing.T) {
	const (
		findingsBound = 64
		extraFiles    = 11
	)
	atBoundRoot := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	plantUnownedSubtreeFiles(t, atBoundRoot, findingsBound)
	atReport, err := Verify(t.Context(), atBoundRoot, catalogFor("HISS-01", "go", StatePartial))
	if err != nil || atReport.Passed() || len(atReport.Findings) != findingsBound {
		t.Fatalf("at-bound subtree: err=%v findings=%d, want %d", err, len(atReport.Findings), findingsBound)
	}

	overRoot := corpusRoot(t, "HISS-01", "go", bucketPositive, "recursion.go", recursiveGo)
	plantUnownedSubtreeFiles(t, overRoot, findingsBound+extraFiles)
	overReport, err := Verify(t.Context(), overRoot, catalogFor("HISS-01", "go", StatePartial))
	if err != nil {
		t.Fatalf("verify over-bound subtree: %v", err)
	}
	if overReport.Passed() || len(overReport.Findings) != findingsBound+1 {
		t.Fatalf("over-bound findings = %d, want %d (%d + 1 summary)",
			len(overReport.Findings), findingsBound+1, findingsBound)
	}
	wantSummary := fmt.Sprintf("%d further unowned file(s) omitted", extraFiles)
	summaries := 0
	for i := 0; i < len(overReport.Findings); i++ {
		if strings.Contains(overReport.Findings[i].Detail, wantSummary) {
			summaries++
		}
	}
	if summaries != 1 {
		t.Fatalf("summary findings containing %q = %d, want 1 in %+v", wantSummary, summaries, overReport.Findings)
	}
}

// plantUnownedSubtreeFiles writes count unowned files across subdirectories of HISS-01/golnag.
func plantUnownedSubtreeFiles(t *testing.T, root string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		rel := fmt.Sprintf("HISS-01/golnag/dir-%02d/file-%03d.go", i/16, i)
		plantCorpusFile(t, root, rel, cleanGo)
	}
}
