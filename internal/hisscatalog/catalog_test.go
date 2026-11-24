// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hisscatalog

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// catalogSize is the number of invariants the standard defines, HISS-01 through HISS-21.
const catalogSize = 21

// TestCatalog_Positive_ContiguousAndComplete pins the registry the MCP tool and the wiki
// matrix share: every ID from HISS-01 to HISS-21 exactly once, in ascending order, with
// every field filled.
func TestCatalog_Positive_ContiguousAndComplete(t *testing.T) {
	rules := Rules()
	if len(rules) != catalogSize {
		t.Fatalf("catalog has %d rules, want %d", len(rules), catalogSize)
	}
	for i, rule := range rules {
		if want := fmt.Sprintf("HISS-%02d", i+1); rule.ID != want {
			t.Errorf("rule %d is %s, want %s", i, rule.ID, want)
		}
		if rule.Title == "" || rule.Specification == "" || rule.Enforcement == "" || rule.FailureAction == "" {
			t.Errorf("%s has an empty field: %+v", rule.ID, rule)
		}
		if got, ok := LookupRule(rule.ID); !ok || !reflect.DeepEqual(got, rule) {
			t.Errorf("LookupRule(%s) = %+v, %v", rule.ID, got, ok)
		}
	}
	if ids := RuleIDs(); len(ids) != catalogSize || ids[0] != "HISS-01" || ids[catalogSize-1] != "HISS-21" {
		t.Errorf("RuleIDs() = %v", ids)
	}
}

// TestCatalog_Negative_CopyAndUnknownLookup proves a caller cannot edit the registry through
// Rules's result, and that lookup is exact.
func TestCatalog_Negative_CopyAndUnknownLookup(t *testing.T) {
	rules := Rules()
	rules[0].Title = "tampered"
	rules[0].Directive[0].Text = "tampered"
	looked, _ := LookupRule("HISS-02")
	looked.Directive[0].Text = "tampered"
	if got, _ := LookupRule("HISS-01"); got.Title == "tampered" || got.Directive[0].Text == "tampered" {
		t.Error("editing Rules()'s result changed the registry")
	}
	if got, _ := LookupRule("HISS-02"); got.Directive[0].Text == "tampered" {
		t.Error("editing LookupRule's result changed the registry")
	}
	for _, id := range []string{"", "HISS-00", "HISS-22", "hiss-01", " HISS-01", "HISS-1"} {
		if _, ok := LookupRule(id); ok {
			t.Errorf("LookupRule(%q) found a rule", id)
		}
	}
}

// TestRuleExplanation_Boundary_ListSpecification pins both specification shapes: prose
// follows the label on its line, a list opens on the next line with no trailing space.
func TestRuleExplanation_Boundary_ListSpecification(t *testing.T) {
	prose, _ := LookupRule("HISS-12")
	if want := "Rule: HISS-12 (Secret Leak Prevention)\nFormal Specification: Zero credentials in Git history.\n" +
		"Enforcement: 'make secrets' and 'praetorctl security secrets' (in adopted verify-all and lefthook pre-push) run gitleaks over repository history.\n" +
		"Failure Action: Verification gate rejection."; prose.Explanation() != want {
		t.Errorf("HISS-12 explanation = %q, want %q", prose.Explanation(), want)
	}
	list, _ := LookupRule("HISS-04")
	if !strings.Contains(list.Explanation(), "Formal Specification:\n  - McCabe Cyclomatic Complexity <= 10\n") {
		t.Errorf("HISS-04 explanation does not open its list on a new line: %q", list.Explanation())
	}
}

// specFuncLength matches the function-length line of a rule's formal specification.
var specFuncLength = regexp.MustCompile(`Function Length <= (\d+) LOC`)

// Negative: the 75-line copy the specification used to carry is gone, and the cyclomatic cap
// on the line above is not read as a function length.
func TestRuleExplanation_Negative_HISS04DropsTheStaleFuncLOC(t *testing.T) {
	rule, _ := LookupRule("HISS-04")
	if strings.Contains(rule.Explanation(), "<= 75 LOC") {
		t.Fatalf("HISS-04 still states the stale 75-line length: %q", rule.Explanation())
	}
	if got := specFuncLength.FindAllString("McCabe Cyclomatic Complexity <= 10", -1); len(got) != 0 {
		t.Fatalf("a cyclomatic cap read as a function length: %v", got)
	}
}

// TestParseGatedInvariants_Positive_CanonicalAgents reads the repository's own AGENTS.md:
// its table must parse, and every row must be a catalog invariant.
func TestParseGatedInvariants_Positive_CanonicalAgents(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseGatedInvariants(string(data))
	if err != nil {
		t.Fatalf("ParseGatedInvariants(AGENTS.md): %v", err)
	}
	if len(rows) == 0 || rows[0].ID != "HISS-01" || rows[0].Scope != "control flow" {
		t.Fatalf("first gated row = %+v", rows)
	}
	first := rows[0]
	if first.Rule != "recursion prohibited; call graph = DAG" || first.Enforcement != "build" || first.OnFail != "immediate build failure" {
		t.Errorf("HISS-01 cells = %+v", first)
	}
}

// gatedFixture wraps table rows in the section AGENTS.md carries them in.
func gatedFixture(rows ...string) string {
	return "# Harness\n\n" + GatedInvariantsHeading + "\n\n" +
		"| Invariant | Rule | Enforcement | On fail |\n| :--- | :--- | :--- | :--- |\n" +
		strings.Join(rows, "\n") + "\n\n## Operational Rules\n\n1. text\n"
}

func TestParseGatedInvariants_Negative_RejectsUnreadableTables(t *testing.T) {
	cases := map[string]struct {
		doc  string
		want error
	}{
		"no section":    {"# Harness\n\n| **HISS-01** x | a | b | c |\n", ErrNoGatedInvariants},
		"empty section": {gatedFixture(), ErrNoGatedInvariants},
		"unknown invariant": {
			gatedFixture("| **HISS-01** control flow | a | b | c |", "| **HISS-99** invented | a | b | c |"),
			ErrUnknownInvariant,
		},
		"duplicate invariant": {
			gatedFixture("| **HISS-01** control flow | a | b | c |", "| **HISS-01** again | a | b | c |"),
			ErrDuplicateInvariant,
		},
		"row only after the section": {
			"# Harness\n\n" + GatedInvariantsHeading + "\n\ntext\n\n## Other\n\n| **HISS-01** x | a | b | c |\n",
			ErrNoGatedInvariants,
		},
	}
	for name, tc := range cases {
		if _, err := ParseGatedInvariants(tc.doc); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

// TestParseGatedInvariants_Boundary_SectionEdgesAndCells covers the edges of the grammar: a
// suffixed heading, CRLF line endings, an escaped pipe, a fenced shell comment inside the
// section, and a row after the next heading that must not be read.
func TestParseGatedInvariants_Boundary_SectionEdgesAndCells(t *testing.T) {
	doc := "# Harness\r\n\r\n" + GatedInvariantsHeading + " (Modernized)\r\n\r\n" +
		"| **HISS-02** loops, I/O | a \\| b | Semgrep / AST | error |\r\n" +
		"```bash\r\n# not a heading\r\n```\r\n" +
		"| **HISS-16** context integrity | one source | pre-commit | blocker |\r\n" +
		"\r\n## Operational Rules\r\n| **HISS-17** state ledger | x | y | z |\r\n"
	rows, err := ParseGatedInvariants(doc)
	if err != nil {
		t.Fatalf("ParseGatedInvariants: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "HISS-02" || rows[1].ID != "HISS-16" {
		t.Fatalf("rows = %+v, want HISS-02 and HISS-16 only", rows)
	}
	if rows[0].Scope != "loops, I/O" || rows[0].Rule != "a | b" || rows[1].OnFail != "blocker" {
		t.Errorf("cells = %+v", rows)
	}

	tooLong := strings.Repeat("\n", maxGatedTableLines)
	if _, err := ParseGatedInvariants(tooLong); !errors.Is(err, ErrGatedTableTooLong) {
		t.Errorf("a document past the line bound: err = %v, want ErrGatedTableTooLong", err)
	}
}

// TestSplitInvariantRow_Positive_AnyBoldID: the splitter reads a catalog row and a
// repository's own row alike, with the line kept as written and the cells split.
func TestSplitInvariantRow_Positive_AnyBoldID(t *testing.T) {
	for line, want := range map[string]InvariantRow{
		"| **HISS-01** control flow | recursion prohibited | build | immediate build failure |": {
			ID: "HISS-01", Cells: []string{"control flow", "recursion prohibited", "build", "immediate build failure"},
		},
		"  | **ACME-01** secrets | never log tokens | review |  ": {
			ID: "ACME-01", Cells: []string{"secrets", "never log tokens", "review"},
		},
	} {
		got, ok := SplitInvariantRow(line)
		want.Line = strings.TrimSpace(line)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("SplitInvariantRow(%q) = %+v, %v; want %+v", line, got, ok, want)
		}
	}
}

// TestSplitInvariantRow_Negative_NotARow: the header, the delimiter row, prose, a row without
// a bold ID and an unterminated row are no invariant rows.
func TestSplitInvariantRow_Negative_NotARow(t *testing.T) {
	for _, line := range []string{
		"| Invariant | Rule | Adopted check | On fail |",
		"| :--- | :--- | :--- | :--- |",
		"old table",
		"",
		"|",
		"| HISS-01 control flow | a | b | c |",
		"| **HISS-01** control flow | a | b | c",
		"| **HISS 01** control flow | a | b | c |",
	} {
		if row, ok := SplitInvariantRow(line); ok {
			t.Errorf("SplitInvariantRow(%q) = %+v, want no row", line, row)
		}
	}
}

// TestSplitInvariantRow_Boundary_EscapedPipes: an escaped pipe stays inside its cell and is
// restored, a closing escaped pipe leaves the row unterminated, and ParseGatedInvariants skips
// a repository's own row between catalog rows instead of rejecting it.
func TestSplitInvariantRow_Boundary_EscapedPipes(t *testing.T) {
	row, ok := SplitInvariantRow(`| **ACME-02** a \| b | c \| d |`)
	if !ok || row.ID != "ACME-02" || !reflect.DeepEqual(row.Cells, []string{"a | b", "c | d"}) {
		t.Fatalf("escaped pipes: %+v, %v", row, ok)
	}
	if row, ok := SplitInvariantRow(`| **ACME-02** a | b \|`); ok {
		t.Errorf("a closing escaped pipe must not close the row: %+v", row)
	}
	rows, err := ParseGatedInvariants(gatedFixture(
		"| **HISS-01** control flow | a | b | c |",
		`| **ACME-01** own \| rule | x | y | z |`,
		"| **HISS-02** loops | a | b | c |"))
	if err != nil || len(rows) != 2 || rows[0].ID != "HISS-01" || rows[1].ID != "HISS-02" {
		t.Fatalf("ParseGatedInvariants = %+v, %v; want HISS-01 and HISS-02 only", rows, err)
	}
	table, err := InvariantTableRows(gatedFixture("| **HISS-01** control flow | a | b | c |", "| **ACME-01** own | x | y | z |"))
	if err != nil || len(table) != 2 || table[1].ID != "ACME-01" {
		t.Fatalf("InvariantTableRows = %+v, %v; want both rows", table, err)
	}
	if table, err := InvariantTableRows("# Harness\n\n| **ACME-01** own | x | y | z |\n"); err != nil || len(table) != 0 {
		t.Errorf("a row outside the section: %+v, %v", table, err)
	}
}

// maxHISSSourceFiles bounds the files read when deriving emitted rule IDs from internal/hiss.
const maxHISSSourceFiles = 256

// emittedScannerRuleIDs parses the production Go sources of internal/hiss and returns the sorted
// HISS rule IDs passed directly to recordViolation or goScanner.record.
func emittedScannerRuleIDs(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "hiss")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	set := make(map[string]struct{})
	for i := 0; i < len(entries) && i < maxHISSSourceFiles; i++ {
		name := entries[i].Name()
		if entries[i].IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		collectEmittedFileRules(t, filepath.Join(dir, name), set)
	}
	return slices.Sorted(maps.Keys(set))
}

// collectEmittedFileRules records every HISS rule literal emitted as a violation in path.
func collectEmittedFileRules(t *testing.T, path string, set map[string]struct{}) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ruleID, emitted := emittedCallRuleID(call); emitted {
			set[ruleID] = struct{}{}
		}
		return true
	})
}

// emittedCallRuleID extracts the HISS rule ID literal from a recordViolation or .record call.
func emittedCallRuleID(call *ast.CallExpr) (string, bool) {
	argIndex := callRuleArgIndex(call.Fun)
	if argIndex < 0 || argIndex >= len(call.Args) {
		return "", false
	}
	lit, ok := call.Args[argIndex].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil && strings.HasPrefix(value, "HISS-")
}

// callRuleArgIndex returns the argument index carrying the HISS rule ID on violation helper calls.
func callRuleArgIndex(fun ast.Expr) int {
	switch target := fun.(type) {
	case *ast.Ident:
		if target.Name == "recordViolation" {
			return 1
		}
	case *ast.SelectorExpr:
		if target.Sel.Name == "record" {
			return 0
		}
	}
	return -1
}

// TestScannerRuleIDs_MatchesEmittedScannerRules verifies that the catalog's typed scanner
// ownership equals the set of rule IDs internal/hiss can emit as violations.
func TestScannerRuleIDs_MatchesEmittedScannerRules(t *testing.T) {
	want := emittedScannerRuleIDs(t)
	if len(want) == 0 {
		t.Fatal("no emitted rule IDs discovered in internal/hiss")
	}
	got := ScannerRuleIDs()
	if !slices.Equal(got, want) {
		t.Fatalf("ScannerRuleIDs() = %v, want %v", got, want)
	}
}

// TestScannerRuleIDs_WordingChangeDoesNotAlterRouting proves that editing explanatory English in
// catalog entries cannot add or remove scanner routing.
func TestScannerRuleIDs_WordingChangeDoesNotAlterRouting(t *testing.T) {
	want := ScannerRuleIDs()
	saved := slices.Clone(catalog)
	t.Cleanup(func() { copy(catalog, saved) })

	for i := 0; i < len(catalog); i++ {
		switch catalog[i].ID {
		case "HISS-01", "HISS-02", "HISS-04":
			catalog[i].Title = "Reworded title"
			catalog[i].Specification = "Reworded specification."
			catalog[i].Enforcement = "Static check without naming the package."
			catalog[i].FailureAction = "Reworded failure."
		case "HISS-03", "HISS-10":
			catalog[i].Enforcement = "The internal/hiss scanner decides this rule in prose only."
		}
	}
	if got := ScannerRuleIDs(); !slices.Equal(got, want) {
		t.Fatalf("after prose wording edit, ScannerRuleIDs() = %v, want %v", got, want)
	}
}

// TestScannerRuleIDs_Control_HISS01And02IncludedHISS10Excluded is the baseline control holding
// both before and after typed scanner routing.
func TestScannerRuleIDs_Control_HISS01And02IncludedHISS10Excluded(t *testing.T) {
	ids := ScannerRuleIDs()
	if !slices.Contains(ids, "HISS-01") || !slices.Contains(ids, "HISS-02") || slices.Contains(ids, "HISS-10") {
		t.Fatalf("control expectation violated: ScannerRuleIDs() = %v", ids)
	}
}
