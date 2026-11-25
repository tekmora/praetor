package ruleregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// TestAudit_EvidenceResolution verifies local structural resolution sets status present without Enforced.
func TestAudit_EvidenceResolution(t *testing.T) {
	root := fixtureRoot(t, fixtureRegistry(t))
	report, err := Audit(t.Context(), root)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusPresent || row.Enforced || row.Evidence != "resolved" || row.ProseOnly {
		t.Fatalf("HISS-01 = %#v, want status=present, enforced=false, resolved", row)
	}
}

// TestAudit_EvidenceResolutionGuidanceAndCounts verifies prose-only rules report status guidance and the status counts.
func TestAudit_EvidenceResolutionGuidanceAndCounts(t *testing.T) {
	root := fixtureRoot(t, fixtureRegistry(t))
	report, err := Audit(t.Context(), root)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	prose := findRow(t, report, "HISS-02")
	if prose.Status != StatusGuidance || prose.Enforced || !prose.ProseOnly || prose.Evidence != "prose-only" {
		t.Fatalf("HISS-02 = %#v, want status=guidance, prose-only", prose)
	}
	counts := report.StatusCounts()
	if counts[StatusPresent] != 1 || counts[StatusGuidance] != len(report.Rows)-1 {
		t.Fatalf("StatusCounts() = %#v", counts)
	}
}

// TestAudit_EmptyMakeTargetFails verifies Make targets without prerequisites or recipe lines fail resolution.
func TestAudit_EmptyMakeTargetFails(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "empty-make")
	report, err := Audit(t.Context(), repo)
	if err == nil {
		t.Fatal("Audit(empty-make) error = nil, want unresolved empty Make target")
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusUnresolved || row.Enforced || row.Evidence != "unresolved: make:empty" {
		t.Fatalf("empty-make HISS-01 = %#v", row)
	}
}

// TestAudit_MakeTargetBodyShapes checks literal evidence and the exact diagnostic for refusals.
func TestAudit_MakeTargetBodyShapes(t *testing.T) {
	const registry = "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:verify-all]\n"
	const missing = `HISS-01: unresolved evidence pointer "make:verify-all"`
	const unproven = missing + ": not statically provable"
	tests := [...]struct{ name, makefile, problem string }{
		{"short variable", "D :=\nverify-all: $D\n", unproven},
		{"parenthesized variable", "D := lint\nverify-all: $(D)\n", unproven},
		{"braced variable", "D := lint\nverify-all: ${D}\n", unproven},
		{"static pattern", "verify-all: %:\n", unproven},
		{"double colon", "verify-all::\n", unproven},
		{"double colon with prerequisite", "verify-all:: lint\n", unproven},
		{"conditional rule", "ifeq 'a' 'b'\nverify-all: lint\nendif\n", unproven},
		{"continued rule", "verify-all: \\\n  lint\n", unproven},
		{"continued recipe after literal body", "verify-all: lint\n\t@true\n\t@echo \\\n  ok\n", unproven},
		{"recipe variable", "verify-all:\n\t$(MAKE) lint\n", unproven},
		{"escaped blank in head", "release\\ verify-all: ; @true\n", unproven},
		{"empty inline semicolon", "verify-all: ;\n", unproven},
		{"comment only", "verify-all: # no body\n", unproven},
		{"whitespace tab line", "verify-all:\n\t   \n", unproven},
		{"tab comment", "verify-all:\n\t# explanatory note\n", unproven},
		{"prerequisite without recipe", "verify-all: lint\n", unproven},
		{"inline semicolon recipe", "verify-all: ; @true\n", ""},
		{"tab recipe", "verify-all:\n\t@true\n", ""},
		{"literal file", "# targets\nMODE := fast\nall: verify-all\nverify-all: | out\n\t@true\n", ""},
		{"missing target", "other: lint\n", missing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, registry)
			writeTestFile(t, root, "Makefile", tc.makefile)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.problem != "")
			if tc.problem != "" && !slices.Contains(report.Problems, tc.problem) {
				t.Fatalf("problems = %v, want %q", report.Problems, tc.problem)
			}
		})
	}
}

// TestAudit_MakeWholeFile verifies that an unsupported file defeats even a matching forge assertion.
func TestAudit_MakeWholeFile(t *testing.T) {
	const rule = "check: ; @true\n"
	const registry = "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: "
	t.Run("phony literal rule", func(t *testing.T) {
		root := fixtureRoot(t, registry+"[make:check]\n")
		writeTestFile(t, root, "Makefile", ".PHONY: check\n"+rule)
		report, err := Audit(t.Context(), root)
		assertLocalEvidenceStatus(t, report, err, false)
	})
	opts := forgeOptions(ForgeRequiredSignatures, forgeState("required", "required", true, true), nil)
	for _, tc := range [...]struct{ name, makefile string }{
		{"later empty recipe", rule + "check: ;\n"},
		{"later rule without recipe", rule + "other check: dep\n"},
		{"suffix remake", rule + ".SUFFIXES: .next\n.next: ; cp Makefile.next Makefile\n"},
		{"suffix list alone", rule + ".SUFFIXES: .next\n"},
		{"single suffix", rule + ".next: ; @true\n"},
		{"double suffix", rule + ".next.mk: ; @true\n"},
		{"dot target in list", rule + "other .DEFAULT: ; @true\n"},
		{"dot-prefixed path", rule + "./other: ; @true\n"},
		{"implicit source prerequisite", rule + "other: Makefile.c\n"},
		{"pattern rule", rule + "%: %.next\n"},
		{"pattern prerequisite", rule + "other: | %.next\n"},
		{"static pattern rule", rule + "other: %: %.next\n"},
		{"VPATH assignment", rule + "VPATH := src\n"},
		{"vpath directive", rule + "vpath %.mk src\n"},
		{"remade Makefile", rule + "Makefile: next.mk ; cp next.mk Makefile\n"},
		{"included recipe prefix", "include settings.mk\ncheck:\n\tX := one\n"},
		{"optional include", rule + "-include settings.mk\n"},
		{"explicit prefix", rule + ".RECIPEPREFIX := >\n"},
		{"define", rule + "define FLAGS\none\nendef\n"},
		{"export", rule + "export MODE := fast\n"},
		{"BOM hides conditional", "\ufeffifeq (a,b)\ncheck: dep\nendif\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, registry+"[make:check, forge:required_signatures]\n")
			writeTestFile(t, root, "settings.mk", ".RECIPEPREFIX := >\n")
			writeTestFile(t, root, "Makefile", tc.makefile)
			report, err := AuditWithOptions(t.Context(), root, opts)
			assertLocalEvidenceStatus(t, report, err, true)
			if !slices.Contains(report.Problems, `HISS-01: unresolved evidence pointer "make:check": not statically provable`) {
				t.Fatalf("problems = %v", report.Problems)
			}
		})
	}
}

// TestAudit_MakeImplicitSource checks the selected makefile and its directory before claiming a recipe.
func TestAudit_MakeImplicitSource(t *testing.T) {
	for _, tc := range [...]struct {
		file, sibling string
		unproven      bool
	}{
		{"Makefile", "Makefile.sh", true},
		{"Makefile", "Makefile.c", true},
		{"Makefile", "Makefile.o", true},
		{"Makefile", "Makefile,v", true},
		{"Makefile", "RCS/unrelated", true},
		{"Makefile", "s.Makefile", true},
		{"Makefile", "SCCS/s.Makefile", true},
		{"Makefile", "s.Makefile.sh", true},
		{"Makefile", "", false},
		{"Makefile", "README.md", false},
		{"GNUmakefile", "GNUmakefile.sh", true},
		{"GNUmakefile", "Makefile.sh", false},
		{"makefile", "makefile.sh", true},
		{"makefile", "README.md", false},
	} {
		t.Run(tc.file+"/"+tc.sibling, func(t *testing.T) {
			root := pointerFixtureRoot(t, "make:check")
			writeTestFile(t, root, tc.file, "check: ; @true\n")
			old := time.Unix(1_000_000, 0)
			if err := os.Chtimes(filepath.Join(root, tc.file), old, old); err != nil {
				t.Fatal(err)
			}
			if tc.sibling != "" {
				writeTestFile(t, root, tc.sibling, "check: ;\n")
			}
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.unproven)
			if tc.unproven && !strings.Contains(strings.Join(report.Problems, "\n"), "not statically provable") {
				t.Fatalf("problems = %v", report.Problems)
			}
		})
	}
}

// TestAudit_MakeImplicitSourceWithForge checks that a matching forge assertion cannot rescue either recipe.
func TestAudit_MakeImplicitSourceWithForge(t *testing.T) {
	root := pointerFixtureRoot(t, "make:check, make:second, forge:required_signatures")
	writeTestFile(t, root, "Makefile", "check: ; @true\nsecond: ; @true\n")
	writeTestFile(t, root, "Makefile.sh", "check: ;\nsecond: ;\n")
	opts := forgeOptions(ForgeRequiredSignatures, forgeState("required", "required", true, true), nil)
	report, err := AuditWithOptions(t.Context(), root, opts)
	assertLocalEvidenceStatus(t, report, err, true)
	for _, pointer := range [...]string{"make:check", "make:second"} {
		if !slices.ContainsFunc(report.Problems, func(problem string) bool {
			return strings.Contains(problem, pointer) && strings.Contains(problem, "not statically provable")
		}) {
			t.Fatalf("problems = %v, want sibling-source refusal for %s", report.Problems, pointer)
		}
	}
}

// TestAudit_MakeImplicitSourceCase checks sibling lookup against the fixture filesystem's case behavior.
func TestAudit_MakeImplicitSourceCase(t *testing.T) {
	root := pointerFixtureRoot(t, "make:verify-all")
	writeTestFile(t, root, "MAKEFILE.SH", "verify-all: ;\n")
	_, lookupErr := os.Stat(filepath.Join(root, "Makefile.sh"))
	if lookupErr != nil && !errors.Is(lookupErr, os.ErrNotExist) {
		t.Fatal(lookupErr)
	}
	report, err := Audit(t.Context(), root)
	assertLocalEvidenceStatus(t, report, err, lookupErr == nil)
}

// TestAudit_MakeConditionalTargetBody requires a recipe whose ownership is unconditional.
func TestAudit_MakeConditionalTargetBody(t *testing.T) {
	tests := []struct {
		name      string
		makefile  string
		wantError bool
	}{
		{"recipe inside ifeq", "verify-all:\nifeq (1,1)\n\t@true\nendif\n", true},
		{"recipe after closed ifdef endif", "verify-all:\nifdef CI\nendif\n\t@true\n", true},
		{"directives without recipe", "verify-all:\nifeq (1,1)\nelse\nendif\n", true},
		{"directives without recipe before other target", "verify-all:\nifneq (a,b)\nendif\nother:\n\t@true\n", true},
		{"else branch recipe", "verify-all:\nifeq (1,0)\nelse\n\t@true\nendif\n", true},
	}
	registry := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:verify-all]\n"
	for i := 0; i < len(tests) && i < maxEvidencePointers; i++ {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, registry)
			writeTestFile(t, root, "Makefile", tc.makefile)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// assertLocalEvidenceStatus verifies the audit result and row status for one local evidence pointer.
func assertLocalEvidenceStatus(t *testing.T, report *Report, err error, wantError bool) {
	t.Helper()
	if (err != nil) != wantError {
		t.Fatalf("Audit() error = %v, wantError = %t", err, wantError)
	}
	row := findRow(t, report, "HISS-01")
	if wantError && (row.Status != StatusUnresolved || row.Enforced) {
		t.Fatalf("row = %#v, want unresolved and unenforced", row)
	}
	if !wantError && (row.Status != StatusPresent || row.Enforced) {
		t.Fatalf("row = %#v, want present and unenforced", row)
	}
}

// TestAudit_MakeSharedParserRegressions verifies define blocks, continued recipes, computed target names,
// and rule heads starting with directive prefixes follow the shared Makefile parser.
func TestAudit_MakeSharedParserRegressions(t *testing.T) {
	tests := []struct {
		name, target, makefile string
		wantError              bool
	}{
		{"define endef decoy", "empty", "empty:\n\ndefine M\nempty: ; @true\nendef\n", true},
		{"continued recipe decoy", "empty", "empty:\n\nother:\n\t@echo \\\nempty: ; @true\n", true},
		{"variable expanded target", "verify-all", "GATE := verify-all\n$(GATE): lint\nlint:\n\t@true\n", true},
		{"escaped space in one target", "verify-all", "release\\ verify-all: ; @true\n", true},
		{"unescaped space between targets", "verify-all", "release verify-all: ; @true\n", false},
		{"escaped space in computed target", "verify-all", "PREFIX := release\n$(PREFIX)\\ verify-all: ; @true\n", true},
		{"known empty prerequisites", "verify-all", "DEPS :=\nverify-all: $(DEPS)\n", true},
		{"known nonempty prerequisites", "verify-all", "DEPS := lint\nverify-all: $(DEPS)\n", true},
		{"empty order-only prerequisites", "verify-all", "DEPS :=\nverify-all: | ${DEPS} ; # comment\n", true},
		{"empty prerequisites with recipe", "verify-all", "DEPS :=\nverify-all: $(DEPS) ; @true\n", true},
		{"ifeq quoted rule target", "verify-all", "verify-all:\nifeq\"other\":\n\t@true\n", true},
	}
	for i := 0; i < len(tests) && i < maxEvidencePointers; i++ {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			registry := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:" + tc.target + "]\n"
			root := fixtureRoot(t, registry)
			writeTestFile(t, root, "Makefile", tc.makefile)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
			row := findRow(t, report, "HISS-01")
			wantEvidence := "resolved"
			if tc.wantError {
				wantEvidence = "unresolved: make:" + tc.target
			}
			if row.Evidence != wantEvidence {
				t.Fatalf("row.Evidence = %q, want %q", row.Evidence, wantEvidence)
			}
		})
	}
}

// TestAudit_DisabledWorkflowJobFails verifies workflow jobs with literal false conditions fail resolution.
func TestAudit_DisabledWorkflowJobFails(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "disabled-workflow")
	report, err := Audit(t.Context(), repo)
	if err == nil {
		t.Fatal("Audit(disabled-workflow) error = nil, want unresolved disabled workflow jobs")
	}
	literal := findRow(t, report, "HISS-01")
	if literal.Status != StatusUnresolved || literal.Enforced || literal.Evidence != "unresolved: workflow:ci.yml#literal-false" {
		t.Fatalf("literal-false HISS-01 = %#v", literal)
	}
	expr := findRow(t, report, "HISS-02")
	if expr.Status != StatusUnresolved || expr.Enforced || expr.Evidence != "unresolved: workflow:ci.yml#expr-false" {
		t.Fatalf("expr-false HISS-02 = %#v", expr)
	}
}

// TestAudit_ConditionalWorkflowJobResolvesAsPresent verifies non-false workflow job conditions still resolve.
func TestAudit_ConditionalWorkflowJobResolvesAsPresent(t *testing.T) {
	registry := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [workflow:ci.yml#verify]\n"
	root := fixtureRoot(t, registry)
	writeTestFile(t, root, ".github/workflows/ci.yml", "jobs:\n  verify:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n")
	report, err := Audit(t.Context(), root)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusPresent || row.Enforced || row.Evidence != "resolved" {
		t.Fatalf("HISS-01 = %#v, want status=present, enforced=false", row)
	}
}

// TestAudit_WorkflowDuplicateCondition preserves the parser diagnostic for an invalid job.
func TestAudit_WorkflowDuplicateCondition(t *testing.T) {
	const pointer = "workflow:ci.yml#verify"
	root := pointerFixtureRoot(t, pointer)
	writeTestFile(t, root, ".github/workflows/ci.yml", "jobs:\n  verify:\n    if: true\n    if: false\n")
	assertPointerProblem(t, root, pointer, `mapping key "if" already defined`)
}

// TestAudit_WorkflowDirectory resolves a workflow pointer only in the directory GitHub runs workflows from.
func TestAudit_WorkflowDirectory(t *testing.T) {
	const registry = "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [workflow:"
	for _, file := range [...]string{"ci.yml", "archive/ci.yml", "archive/../ci.yml"} {
		t.Run(file, func(t *testing.T) {
			root := fixtureRoot(t, registry+file+"#verify]\n")
			writeTestFile(t, root, ".github/workflows/archive/ci.yml", "jobs:\n  verify:\n    runs-on: ubuntu-latest\n")
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, file != "ci.yml")
		})
	}
}

// TestAudit_LinkedEvidenceDirectory refuses a pointer redirected to another directory inside the repository.
func TestAudit_LinkedEvidenceDirectory(t *testing.T) {
	tests := [...]struct{ pointer, dir string }{
		{"workflow:ci.yml#verify", ".github"},
		{"workflow:ci.yml#verify", ".github/workflows"},
		{"test:internal/check.TestEnforced", "internal/check"},
	}
	for _, tc := range tests {
		t.Run(tc.dir, func(t *testing.T) {
			root := pointerFixtureRoot(t, tc.pointer)
			dir := filepath.Join(root, tc.dir)
			if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "archive")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("archive", dir); err != nil {
				t.Skipf("cannot create directory symlink: %v", err)
			}
			assertPointerProblem(t, root, tc.pointer, "path component must be a directory, never a symlink")
		})
	}
}

// TestAudit_WorkflowJobAlias checks evidence resolution for aliases of jobs and their conditions.
func TestAudit_WorkflowJobAlias(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantError bool
	}{
		{"aliased active job", "jobs:\n  base: &base\n    runs-on: ubuntu-latest\n  verify: *base\n", false},
		{"aliased conditional active job", "jobs:\n  base: &base\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n  verify: *base\n", false},
		{"alias of literal false job", "jobs:\n  disabled: &disabled\n    if: false\n    runs-on: ubuntu-latest\n  verify: *disabled\n", true},
		{"alias of expression false job", "jobs:\n  disabled: &disabled\n    if: ${{ false }}\n    runs-on: ubuntu-latest\n  verify: *disabled\n", true},
		{"aliased active condition", "jobs:\n  base:\n    if: &condition github.event_name == 'push'\n  verify:\n    if: *condition\n", false},
		{"aliased false condition", "jobs:\n  base:\n    if: &condition false\n  verify:\n    if: *condition\n", true},
		{"merged false", "jobs:\n  verify: {<<: {if: false}, runs-on: ubuntu-latest}\n", true},
		{"merged active", "jobs:\n  verify: {<<: {if: true}, runs-on: ubuntu-latest}\n", true},
		{"merged ancestor", "jobs:\n  <<: {base: {runs-on: ubuntu-latest}}\n  verify: {if: true}\n", true},
		{"mixed case false", "jobs:\n  verify:\n    if: False\n", true},
		{"aliased uppercase false", "jobs:\n  base:\n    if: &condition FALSE\n  verify:\n    if: *condition\n", true},
		{"uppercase true", "jobs:\n  verify:\n    if: TRUE\n", false},
		{"condition alias without anchor", "jobs:\n  verify:\n    if: *missing\n", true},
	}
	registry := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [workflow:ci.yml#verify]\n"
	for i := 0; i < len(tests) && i < maxEvidencePointers; i++ {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, registry)
			writeTestFile(t, root, ".github/workflows/ci.yml", tc.workflow)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// TestUnwrapYAMLAliasNilTarget covers an incomplete alias node directly.
func TestUnwrapYAMLAliasNilTarget(t *testing.T) {
	if got := unwrapYAMLAlias(&yaml.Node{Kind: yaml.AliasNode}); got != nil {
		t.Fatalf("unwrapYAMLAlias(alias without target) = %v, want nil", got)
	}
}

// TestAudit_PresentTestNotEnforced verifies an existing test pointer reports status present and enforced false.
func TestAudit_PresentTestNotEnforced(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "present-test")
	report, err := Audit(t.Context(), repo)
	if err != nil {
		t.Fatalf("Audit(present-test) error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusPresent || row.Enforced || row.Evidence != "resolved" {
		t.Fatalf("present-test HISS-01 = %#v, want status=present, enforced=false", row)
	}
	if !slices.Contains(report.UnenforcedIDs(), "HISS-01") {
		t.Fatalf("UnenforcedIDs() = %v, want HISS-01 included", report.UnenforcedIDs())
	}
}

// TestAudit_TestDeclaration resolves a test pointer only to a parsed top-level test declaration.
func TestAudit_TestDeclaration(t *testing.T) {
	const declaration = "func TestGhost(t *testing.T) {}\n"
	const registry = "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [test:internal/check.TestGhost]\n"
	tests := [...]struct {
		name, source string
		wantError    bool
	}{
		{"block comment", "/*\n" + declaration + "*/\n", true},
		{"raw string", "const example = `\n" + declaration + "`\n", true},
		{"method", "type runner struct{}\nfunc (runner) TestGhost(t *testing.T) {}\n", true},
		{"wrong signature", "func TestGhost() {}\n", true},
		{"test function", declaration, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, registry)
			writeTestFile(t, root, "internal/check/check_test.go", "package check\nimport \"testing\"\n"+tc.source)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// TestAudit_TestNames checks cmd/go's prefix boundary against parsed declarations.
func TestAudit_TestNames(t *testing.T) {
	tests := [...]struct {
		name      string
		wantError bool
	}{
		{"Test", false},
		{"TestÉ", false},
		{"Testé", true},
		{"Testcase", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestFile(t, root, "check/check.go", "package check\n")
			writeTestFile(t, root, "check/names_test.go", "package check\nimport \"testing\"\nfunc "+tc.name+"(*testing.T) {}\n")
			err := resolve(t.Context(), root, "test:check."+tc.name)
			if (err != nil) != tc.wantError {
				t.Fatalf("resolve(%s) error = %v, wantError = %t", tc.name, err, tc.wantError)
			}
		})
	}
}

// TestAudit_TestParameterImport checks the type binding in the file that declares the test.
func TestAudit_TestParameterImport(t *testing.T) {
	tests := [...]struct {
		name, preamble, parameter string
		wantError                 bool
	}{
		{"local type", "type T struct{}", "*T", true},
		{"missing import", "", "*testing.T", true},
		{"other import", `import testing "example.com/other"`, "*testing.T", true},
		{"blank import", `import _ "testing"` + "\ntype T struct{}", "*T", true},
		{"renamed import", `import check "testing"`, "*check.T", false},
		{"dot import", `import . "testing"`, "*T", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := pointerFixtureRoot(t, "test:internal/check.TestGhost")
			source := "package check\n" + tc.preamble + "\nfunc TestGhost(" + tc.parameter + ") {}\n"
			writeTestFile(t, root, "internal/check/ghost_test.go", source)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// TestAudit_TestPackageFiles checks package clauses and build constraints independently of directory names.
func TestAudit_TestPackageFiles(t *testing.T) {
	const function = "\nimport \"testing\"\nfunc TestGhost(*testing.T) {}\n"
	for _, tc := range [...]struct {
		name, production, test string
		wantError              bool
	}{
		{"internal", "package example", "package example", false},
		{"external", "package example", "package example_test", false},
		{"documentation", "package example", "package documentation", true},
		{"wrong package", "package example", "package check", true},
		{"wrong external", "package example", "package check_test", true},
		{"go build", "package example", "//go:build ignore\n\npackage example", true},
		{"plus build", "package example", "// +build ignore\n\npackage example_test", true},
		{"test only", "", "package check", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := pointerFixtureRoot(t, "test:check.TestGhost")
			if tc.production != "" {
				writeTestFile(t, root, "check/base.go", tc.production+"\n")
			}
			writeTestFile(t, root, "check/ghost_test.go", tc.test+function)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// TestAudit_TestFilenameConstraints requires portable files for all three parts of the evidence.
func TestAudit_TestFilenameConstraints(t *testing.T) {
	const pointer = "test:check.TestGate"
	for _, tc := range [...]struct {
		name, base, alias, test string
		wantError               bool
	}{
		{"OS test", "base.go", "alias_test.go", "gate_windows_test.go", true},
		{"architecture test", "base.go", "alias_test.go", "gate_amd64_test.go", true},
		{"OS and architecture test", "base.go", "alias_test.go", "gate_linux_arm64_test.go", true},
		{"OS package", "base_linux.go", "alias_test.go", "gate_test.go", true},
		{"architecture alias", "base.go", "alias_arm64_test.go", "gate_test.go", true},
		{"OS without prefix", "base.go", "alias_test.go", "windows_test.go", false},
		{"non-platform suffix", "base.go", "alias_test.go", "gate_portable_test.go", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := pointerFixtureRoot(t, pointer)
			writeTestFile(t, root, "check/"+tc.base, "package check\n")
			writeTestFile(t, root, "check/"+tc.alias, "package check\nimport \"testing\"\ntype T = testing.T\n")
			writeTestFile(t, root, "check/"+tc.test, "package check\nfunc TestGate(*T) {}\n")
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// TestAudit_TestBuildHeader checks whether a malformed neighbor belongs to an otherwise provable package.
func TestAudit_TestBuildHeader(t *testing.T) {
	const pointer = "test:internal/check.TestEnforced"
	const malformed = "package check\nfunc unfinished(\n"
	for _, tc := range [...]struct {
		name, source string
		wantParseErr bool
	}{
		{"modern", "//go:build ignore\n\n" + malformed, false},
		{"negated", "/* license */\n//go:build !windows\n\n" + malformed, false},
		{"legacy", "// +build !windows\n\n" + malformed, false},
		{"unconstrained", malformed, true},
		{"empty", "", true},
		{"legacy package comment", "// +build !windows\n" + malformed, true},
		{"block comment text", "/*\n//go:build ignore\n*/\n" + malformed, true},
		{"split directive keyword", "//go:\rbuild ignore\n\n" + malformed, true},
		{"body comment", "package check\n//go:build ignore\nfunc unfinished(\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := pointerFixtureRoot(t, pointer)
			writeTestFile(t, root, "internal/check/generator.go", tc.source)
			if tc.wantParseErr {
				assertPointerProblem(t, root, pointer, "parse generator.go:")
				return
			}
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, false)
		})
	}
}

// TestAudit_TestParameterAlias checks package-scoped literal aliases and rejects other type bindings.
func TestAudit_TestParameterAlias(t *testing.T) {
	const alias = "import std \"testing\"\ntype T = std.T\n"
	const direct = "package check\n" + alias
	const test = "package check\nfunc Test(*T) {}\n"
	for _, tc := range [...]struct {
		name, file, source, test string
		wantError                bool
	}{
		{"same file", "gate_test.go", "package check\nimport \"testing\"\ntype T = testing.T\nfunc Test(*T) {}\n", "", false},
		{"alias named TT", "gate_test.go", "package check\nimport \"testing\"\ntype TT = testing.T\nfunc Test(*TT) {}\n", "", true},
		{"renamed import", "gate_test.go", "package check\nimport tt \"testing\"\nfunc Test(*tt.T) {}\n", "", false},
		{"later test file", "zz_test.go", direct, test, false},
		{"ordinary source", "types.go", direct, test, false},
		{"external test package", "zz_test.go", "package check_test\n" + alias, "package check_test\nfunc Test(*T) {}\n", false},
		{"different package", "zz_test.go", "package check_test\n" + alias, test, true},
		{"constrained alias", "zz_test.go", "//go:build ignore\n\n" + direct, test, true},
		{"legacy constrained source", "types.go", "// +build ignore\n\n" + direct, test, true},
		{"cgo-only alias", "types.go", "package check\nimport \"C\"\n" + alias, test, true},
		{"alias of alias", "zz_test.go", "package check\nimport \"testing\"\ntype Base = testing.T\ntype T = Base\n", test, true},
		{"defined type", "zz_test.go", "package check\nimport \"testing\"\ntype T testing.T\n", test, true},
		{"unrelated import", "zz_test.go", "package check\nimport std \"example.com/other\"\ntype T = std.T\n", test, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := pointerFixtureRoot(t, "test:internal/check.Test")
			writeTestFile(t, root, "internal/check/"+tc.file, tc.source)
			if tc.test != "" {
				writeTestFile(t, root, "internal/check/gate_test.go", tc.test)
			}
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, tc.wantError)
		})
	}
}

// hookSnapshotContext runs a fixture action when a confined read starts its per-snapshot timeout.
type hookSnapshotContext struct {
	context.Context
	beforeRead func()
}

// Deadline forwards the test deadline after preparing the next version of the fixture.
func (c hookSnapshotContext) Deadline() (time.Time, bool) {
	c.beforeRead()
	return c.Context.Deadline()
}

// TestAudit_HookSnapshot replaces the config with malformed YAML if command lookup opens it again.
func TestAudit_HookSnapshot(t *testing.T) {
	const pointer = "hook:commit-msg.message-policy"
	root := pointerFixtureRoot(t, pointer)
	reads := 0
	ctx := hookSnapshotContext{Context: t.Context(), beforeRead: func() {
		reads++
		if reads == 2 {
			writeTestFile(t, root, "lefthook.yml", "commit-msg: [\n")
		}
	}}
	if err := resolve(ctx, root, pointer); err != nil || reads != 1 {
		t.Fatalf("resolve = %v after %d reads, want command from the first snapshot", err, reads)
	}
}

// TestAudit_HookCause checks that a malformed extension list retains its typed YAML diagnostic.
func TestAudit_HookCause(t *testing.T) {
	const pointer = "hook:pre-commit.lint"
	root := pointerFixtureRoot(t, pointer)
	writeTestFile(t, root, "lefthook.yml", "extends: {unexpected: mapping}\n")
	err := resolve(t.Context(), root, pointer)
	var cause *yaml.TypeError
	if !errors.As(err, &cause) || !strings.Contains(err.Error(), pointer) {
		t.Fatalf("resolve = %v, want pointer and *yaml.TypeError", err)
	}
	report, auditErr := Audit(t.Context(), root)
	assertLocalEvidenceStatus(t, report, auditErr, true)
	if !errors.As(auditErr, &cause) || !strings.Contains(strings.Join(report.Problems, "\n"), cause.Error()) {
		t.Fatalf("Audit = %v, problems = %v, want YAML cause", auditErr, report.Problems)
	}
	const extension = ".config/lefthook/extra.yml"
	writeTestFile(t, root, "lefthook.yml", "extends: ["+extension+"]\npre-commit:\n  commands:\n    lint: {}\n")
	writeTestFile(t, root, extension, "extends: {unexpected: mapping}\n")
	err = resolve(t.Context(), root, pointer)
	if !errors.As(err, &cause) || !strings.Contains(err.Error(), extension) {
		t.Fatalf("resolve = %v, want extension path and *yaml.TypeError despite matching root command", err)
	}
	writeTestFile(t, root, extension, "")
	if err := resolve(t.Context(), root, pointer); err != nil {
		t.Fatalf("resolve with empty extension = %v", err)
	}
}

// TestAudit_TestFileBound resolves a test at the 256-file limit and reports the first excess file count.
func TestAudit_TestFileBound(t *testing.T) {
	const pointer = "test:internal/check.TestEnforced"
	root := pointerFixtureRoot(t, pointer)
	const pkg = "internal/check/"
	for i := 1; i < 256; i++ {
		writeTestFile(t, root, pkg+"extra"+strconv.Itoa(i)+"_test.go", "package check\n")
	}
	report, err := Audit(t.Context(), root)
	assertLocalEvidenceStatus(t, report, err, false)

	writeTestFile(t, root, pkg+"overflow_test.go", "package check\n")
	assertPointerProblem(t, root, pointer, "package exceeds 256 test files (found 257)")
}

// TestAudit_TestFileErrors surfaces a test file's parse and read errors instead of skipping the file.
func TestAudit_TestFileErrors(t *testing.T) {
	tests := [...]struct{ name, source, diagnostic string }{
		{"parse error", "package check\nfunc unfinished(\n", "parse zz_bad_test.go:"},
		{"read error", "\xff", "read zz_bad_test.go:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRoot(t, fixtureRegistry(t))
			writeTestFile(t, root, "internal/check/zz_bad_test.go", tc.source)
			report, err := Audit(t.Context(), root)
			assertLocalEvidenceStatus(t, report, err, true)
			if !strings.Contains(strings.Join(report.Problems, "\n"), tc.diagnostic) {
				t.Fatalf("problems = %v, want %q", report.Problems, tc.diagnostic)
			}
		})
	}
}

// TestAudit_MissingTestFails verifies a missing test function pointer fails resolution.
func TestAudit_MissingTestFails(t *testing.T) {
	registry := strings.Replace(fixtureRegistry(t), "TestEnforced", "TestMissing", 1)
	report, err := Audit(t.Context(), fixtureRoot(t, registry))
	if err == nil {
		t.Fatal("Audit() error = nil, want unresolved evidence")
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusUnresolved || row.Enforced || row.Evidence != "unresolved: test:internal/check.TestMissing" {
		t.Fatalf("HISS-01 = %#v", row)
	}
}

// TestAudit_PointerReadErrors distinguishes unreadable inputs from missing targets and jobs.
func TestAudit_PointerReadErrors(t *testing.T) {
	tests := [...]struct{ pointer, path string }{
		{"make:verify-all", "Makefile"},
		{"workflow:ci.yml#verify", ".github/workflows/ci.yml"},
	}
	for _, tc := range tests {
		t.Run(tc.pointer, func(t *testing.T) {
			root := pointerFixtureRoot(t, tc.pointer)
			writeTestFile(t, root, tc.path, "\xff")
			assertPointerProblem(t, root, tc.pointer, "source must be UTF-8 text")
			if tc.path == "Makefile" {
				assertPointerProblem(t, root, tc.pointer, "not statically provable")
			}
		})
	}
}

// TestAudit_UnresolvablePointersFail verifies unknown pointer kinds, gate stages, and missing Make targets fail.
func TestAudit_UnresolvablePointersFail(t *testing.T) {
	tests := map[string]string{
		"unknown kind":        "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [nosuchkind:value]\n",
		"unknown gate stage":  "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [gate:No Such Stage]\n",
		"missing make target": "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:no-such-target]\n",
	}
	for name, registry := range tests {
		t.Run(name, func(t *testing.T) {
			report, err := Audit(t.Context(), fixtureRoot(t, registry))
			row := findRow(t, report, "HISS-01")
			if err == nil || row.Status != StatusUnresolved || row.Enforced || !strings.HasPrefix(row.Evidence, "unresolved: ") {
				t.Fatalf("Audit() = (%#v, %v), want unresolved pointer", row, err)
			}
		})
	}
}

// TestAudit_ForgeEvidencePositiveOfflineAndRemote verifies forge-pending and forge-observed on testdata/repos/forge-only.
func TestAudit_ForgeEvidencePositiveOfflineAndRemote(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "forge-only")
	offline := forgeState("required", "", false, false)
	report, err := AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredSignatures, offline, nil))
	if err != nil {
		t.Fatalf("offline AuditWithOptions() error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusForgePending || row.Enforced || row.Evidence != "asserted, not read back" || len(row.Forge) != 1 {
		t.Fatalf("offline HISS-01 = %#v, want status=forge-pending, enforced=false", row)
	}

	remote := forgeState("required", "required", true, true)
	report, err = AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredSignatures, remote, nil))
	if err != nil {
		t.Fatalf("remote AuditWithOptions() error = %v", err)
	}
	row = findRow(t, report, "HISS-01")
	if row.Status != StatusForgeObserved || !row.Enforced || !row.Forge[0].Match || row.Forge[0].Observed != "required" {
		t.Fatalf("remote HISS-01 = %#v, want status=forge-observed, enforced=true", row)
	}
}

// TestAudit_ForgeEvidenceNegative verifies mismatched, failed, and unknown forge pointers fail without setting Enforced.
func TestAudit_ForgeEvidenceNegative(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "forge-only")
	drift := forgeState("required", "not enforced", true, false)
	report, err := AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredSignatures, drift, nil))
	if err == nil || !strings.Contains(strings.Join(report.Problems, "\n"),
		"HISS-01: forge setting required_signatures mismatch: asserted required, observed not enforced") {
		t.Fatalf("drift AuditWithOptions() = (%#v, %v)", report, err)
	}
	if row := findRow(t, report, "HISS-01"); row.Status != StatusUnresolved || row.Enforced {
		t.Fatalf("drift HISS-01 = %#v, want unresolved and unenforced", row)
	}

	readErr := errors.New("forge unavailable")
	report, err = AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredSignatures,
		forgeState("required", "", false, false), readErr))
	if err == nil || !strings.Contains(strings.Join(report.Problems, "\n"), "forge readback failed: forge unavailable") {
		t.Fatalf("read error AuditWithOptions() = (%#v, %v)", report, err)
	}

	unknown := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [forge:unknown]\n"
	report, err = Audit(t.Context(), fixtureRoot(t, unknown))
	if err == nil || !strings.Contains(strings.Join(report.Problems, "\n"), `unresolved evidence pointer "forge:unknown"`) {
		t.Fatalf("unknown setting Audit() = (%#v, %v)", report, err)
	}
}

// TestAudit_LocalAndForgePendingNotEnforced verifies resolved local pointers with a pending forge pointer stay unenforced.
func TestAudit_LocalAndForgePendingNotEnforced(t *testing.T) {
	repo := filepath.Join("testdata", "repos", "local-and-forge")
	pending := forgeState("1", "", false, false)
	report, err := AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredChecks, pending, nil))
	if err != nil {
		t.Fatalf("AuditWithOptions(local-and-forge) error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusForgePending || row.Enforced || row.Evidence != "resolved; forge asserted, not read back" {
		t.Fatalf("offline local-and-forge HISS-01 = %#v, want status=forge-pending, enforced=false", row)
	}

	remote := forgeState("1", "1 of 1 required", true, true)
	report, err = AuditWithOptions(t.Context(), repo, forgeOptions(ForgeRequiredChecks, remote, nil))
	if err != nil {
		t.Fatalf("remote AuditWithOptions(local-and-forge) error = %v", err)
	}
	row = findRow(t, report, "HISS-01")
	if row.Status != StatusForgeObserved || !row.Enforced || row.Evidence != "resolved" {
		t.Fatalf("remote local-and-forge HISS-01 = %#v, want status=forge-observed, enforced=true", row)
	}
}

// TestAudit_ForgeAndGateBoundary verifies mixed forge pointers and non-prose candidate suppression.
func TestAudit_ForgeAndGateBoundary(t *testing.T) {
	registry := "version: 1\nrules:\n" +
		"  - id: HISS-01\n    class: ci-gate\n    evidence: [forge:required_signatures, forge:required_checks]\n" +
		"  - id: AGENTS-OP-1\n    class: ci-gate\n    evidence: [make:verify-all]\n"
	root := fixtureRoot(t, registry)
	opts := AuditOptions{Forge: func(_ context.Context) (map[ForgeSetting]ForgeState, error) {
		return map[ForgeSetting]ForgeState{
			ForgeRequiredSignatures: forgeState("required", "required", true, true),
			ForgeRequiredChecks:     forgeState("1", "", false, false),
		}, nil
	}}
	report, err := AuditWithOptions(t.Context(), root, opts)
	if err != nil {
		t.Fatalf("AuditWithOptions() error = %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusForgePending || row.Enforced || row.Evidence != "resolved; forge asserted, not read back" {
		t.Fatalf("partially pending forge HISS-01 = %#v, want forge-pending and enforced=false", row)
	}
	candidate := findRow(t, report, "AGENTS-OP-1")
	if candidate.Status != StatusPresent || candidate.Enforced || candidate.Candidate {
		t.Fatalf("AGENTS-OP-1 = %#v, want status=present, enforced=false, candidate=false", candidate)
	}
}

// forgeState constructs an enforced ForgeState fixture value.
func forgeState(asserted, observed string, readBack, match bool) ForgeState {
	return ForgeState{Asserted: asserted, Observed: observed, ReadBack: readBack, Match: match, AssertedEnforced: true}
}

// forgeOptions builds AuditOptions returning a single setting state and provider error.
func forgeOptions(setting ForgeSetting, state ForgeState, providerErr error) AuditOptions {
	return AuditOptions{Forge: func(_ context.Context) (map[ForgeSetting]ForgeState, error) {
		return map[ForgeSetting]ForgeState{setting: state}, providerErr
	}}
}

// TestAudit_InvalidRegistry verifies schema validation errors for malformed registry declarations.
func TestAudit_InvalidRegistry(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		want     string
	}{
		{"unknown class", "version: 1\nrules:\n  - id: HISS-01\n    class: absent\n    evidence: [make:verify-all]\n", "unknown class"},
		{"unknown id", "version: 1\nrules:\n  - id: HISS-99\n    class: guidance\n", "unknown rule id"},
		{"duplicate id", "version: 1\nrules:\n  - id: HISS-01\n    class: guidance\n  - id: HISS-01\n    class: guidance\n", "duplicate rule id"},
		{"guidance evidence", "version: 1\nrules:\n  - id: HISS-01\n    class: guidance\n    evidence: [make:verify-all]\n", "guidance must not"},
		{"ci no evidence", "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n", "requires evidence"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := Audit(t.Context(), fixtureRoot(t, test.registry))
			if err == nil || !strings.Contains(strings.Join(report.Problems, "\n"), test.want) {
				t.Fatalf("Audit() = (%#v, %v), want %q", report, err, test.want)
			}
		})
	}
}

// TestAudit_EmptyRulesAndMaximumPointer verifies empty rule lists and pointer length boundaries.
func TestAudit_EmptyRulesAndMaximumPointer(t *testing.T) {
	tests := []struct {
		name      string
		registry  string
		wantError bool
	}{
		{"empty", "version: 1\nrules: []\n", false},
		{"maximum pointer", maxPointerRegistry(), false},
		{"exceeds maximum pointer", overMaxPointerRegistry(), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := Audit(t.Context(), fixtureRoot(t, test.registry))
			if (err != nil) != test.wantError {
				t.Fatalf("Audit() error = %v, want error=%t", err, test.wantError)
			}
			if report == nil {
				t.Fatal("Audit() report = nil")
			}
		})
	}
}

// TestAudit_EvidencePointerCount accepts 32 evidence pointers and leaves a rule with 33 unresolved.
func TestAudit_EvidencePointerCount(t *testing.T) {
	registry := "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [forge:required_signatures" +
		strings.Repeat(", make:verify-all", 31)
	opts := forgeOptions(ForgeRequiredSignatures, forgeState("required", "required", true, true), nil)
	report, err := AuditWithOptions(t.Context(), fixtureRoot(t, registry+"]\n"), opts)
	if err != nil {
		t.Fatalf("32 pointers: %v", err)
	}
	row := findRow(t, report, "HISS-01")
	if row.Status != StatusForgeObserved || !row.Enforced {
		t.Fatalf("32 pointers: row = %#v", row)
	}
	provider := opts.Forge
	called := false
	opts.Forge = func(ctx context.Context) (map[ForgeSetting]ForgeState, error) {
		called = true
		return provider(ctx)
	}
	report, err = AuditWithOptions(t.Context(), fixtureRoot(t, registry+", make:missing]\n"), opts)
	if err == nil || !slices.Contains(report.Problems, "HISS-01: evidence exceeds 32 pointers") {
		t.Fatalf("33 pointers: row = %#v, problems = %v, error = %v", findRow(t, report, "HISS-01"), report.Problems, err)
	}
	row = findRow(t, report, "HISS-01")
	if row.Status != StatusUnresolved || row.Enforced || len(row.Forge) != 0 || called {
		t.Fatalf("33 pointers: row = %#v, provider called = %t", row, called)
	}
}

// TestDecode_UnknownField verifies strict YAML field checking rejects unknown keys.
func TestDecode_UnknownField(t *testing.T) {
	_, err := decode([]byte("version: 1\nrules: []\nextra: no\n"))
	if err == nil || !strings.Contains(err.Error(), "field extra") {
		t.Fatalf("decode() error = %v, want unknown field", err)
	}
}

// TestParseOperationalRules_Bounds verifies the 64-entry upper bound on Operational Rules.
func TestParseOperationalRules_Bounds(t *testing.T) {
	for _, count := range []int{64, 65} {
		t.Run("count", func(t *testing.T) {
			rules, err := ParseOperationalRules([]byte(operationalDocument(count)))
			if count == 64 && (err != nil || len(rules) != count) {
				t.Fatalf("ParseOperationalRules(64) = (%d, %v)", len(rules), err)
			}
			if count == 65 && err == nil {
				t.Fatal("ParseOperationalRules(65) error = nil")
			}
		})
	}
}

// TestProhibited_AllowList verifies the prohibition phrase allow-list matcher.
func TestProhibited_AllowList(t *testing.T) {
	tests := map[string]bool{
		"The agent is told not to bypass it.": true,
		"The agent MUST NOT bypass it.":       true,
		"Never bypass it.":                    true,
		"Do not bypass it.":                   false,
		"No bypass is accepted.":              false,
	}
	for text, want := range tests {
		if got := prohibited(text); got != want {
			t.Errorf("prohibited(%q) = %t, want %t", text, got, want)
		}
	}
}

// pointerFixtureRoot declares one local evidence pointer for HISS-01 in a fixture repository.
func pointerFixtureRoot(t *testing.T, pointer string) string {
	t.Helper()
	return fixtureRoot(t, "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: ["+pointer+"]\n")
}

// assertPointerProblem requires an unresolved row and a problem identifying the pointer and its cause.
func assertPointerProblem(t *testing.T, root, pointer, cause string) {
	t.Helper()
	report, err := Audit(t.Context(), root)
	assertLocalEvidenceStatus(t, report, err, true)
	if !slices.ContainsFunc(report.Problems, func(problem string) bool {
		return strings.Contains(problem, pointer) && strings.Contains(problem, cause)
	}) {
		t.Fatalf("problems = %v, want %s and %q", report.Problems, pointer, cause)
	}
}

// fixtureRoot creates a temporary repository tree populated with standard rule evidence targets.
func fixtureRoot(t *testing.T, registry string) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "AGENTS.md", fixtureAgents(t))
	writeTestFile(t, root, File, registry)
	writeTestFile(t, root, "internal/check/check.go", "package check\n")
	writeTestFile(t, root, "internal/check/check_test.go", "package check\nimport \"testing\"\nfunc TestEnforced(t *testing.T) {}\n")
	writeTestFile(t, root, "lefthook.yml", "commit-msg:\n  commands:\n    message-policy:\n      run: test\n")
	maxTarget := strings.Repeat("a", maxPointerLength-len("make:"))
	writeTestFile(t, root, "Makefile", "verify-all:\n\t@true\n"+maxTarget+":\n\t@true\n")
	writeTestFile(t, root, ".github/workflows/ci.yml", "jobs:\n  verify:\n    runs-on: ubuntu-latest\n")
	return root
}

// fixtureAgents reads testdata/AGENTS.md.
func fixtureAgents(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fixtureRegistry reads testdata/enforcement.yaml.
func fixtureRegistry(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "enforcement.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// writeTestFile writes relative under root with mode 0600, creating parent directories with mode 0700.
func writeTestFile(t *testing.T, root, relative, data string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// findRow returns the Row matching id in report or fails the test.
func findRow(t *testing.T, report *Report, id string) Row {
	t.Helper()
	for i := 0; i < len(report.Rows) && i < maxAuditRules; i++ {
		if report.Rows[i].ID == id {
			return report.Rows[i]
		}
	}
	t.Fatalf("row %s not found", id)
	return Row{}
}

// maxPointerRegistry builds a registry containing a Make pointer right at maxPointerLength.
func maxPointerRegistry() string {
	pointer := "make:" + strings.Repeat("a", maxPointerLength-len("make:"))
	return "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [" + pointer + "]\n"
}

// overMaxPointerRegistry builds a registry containing a Make pointer one byte past maxPointerLength.
func overMaxPointerRegistry() string {
	pointer := "make:" + strings.Repeat("a", maxPointerLength-len("make:")+1)
	return "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [" + pointer + "]\n"
}

// operationalDocument generates an AGENTS.md Operational Rules section with count numbered entries.
func operationalDocument(count int) string {
	var builder strings.Builder
	builder.WriteString("## Operational Rules\n")
	for i := 1; i <= count && i <= maxOperationalRules+1; i++ {
		builder.WriteString("\n")
		builder.WriteString(strconv.Itoa(i) + ". Rule.\n")
	}
	builder.WriteString("\n## Text Register\n")
	return builder.String()
}
