// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package config_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/hisscoverage"
)

// languageTargetSample pairs one repository-relative file path and glob for a coverage language.
type languageTargetSample struct {
	path string
	glob string
}

// coverageLanguageTargets maps each .config/hiss/coverage.yaml language to a representative path
// and glob target for exception validation tests.
var coverageLanguageTargets = map[string]languageTargetSample{
	"go":             {path: "pkg/sample.go", glob: "pkg/*.go"},
	"c":              {path: "src/sample.c", glob: "src/*.c"},
	"rust":           {path: "src/sample.rs", glob: "src/*.rs"},
	"python":         {path: "pkg/sample.py", glob: "pkg/*.py"},
	"javascript":     {path: "ui/sample.js", glob: "ui/*.js"},
	"typescript":     {path: "ui/sample.ts", glob: "ui/*.ts"},
	"svelte":         {path: "ui/Sample.svelte", glob: "ui/*.svelte"},
	"shell":          {path: "scripts/sample.sh", glob: "scripts/*.sh"},
	"github-actions": {path: ".github/workflows/ci.yml", glob: ".github/workflows/*.yml"},
	"systemd":        {path: "units/sample.service", glob: "units/*.service"},
	"ansible":        {path: "roles/app/tasks/main.yml", glob: "roles/app/tasks/*.yml"},
	"dockerfile":     {path: "Dockerfile", glob: "docker/Dockerfile*"},
	"compose":        {path: "compose.yaml", glob: "docker/*.yaml"},
}

// scannerRoutingToday is the fixed reference date for scanner exception validation tests.
var scannerRoutingToday = time.Date(2026, time.November, 10, 0, 0, 0, 0, time.UTC)

// buildScannerCellEntry constructs a categorized exception entry for one rule and target.
func buildScannerCellEntry(ruleID, path, glob, fn string) config.Exception {
	entry := config.Exception{
		Rule:     ruleID,
		Path:     path,
		Glob:     glob,
		Function: fn,
		Category: "C",
		Entered:  "2026-11-10",
		Expires:  "2026-11-20",
		Reason:   "scanner exception routing contract",
	}
	if ruleID == config.ExceptionRuleSecrets {
		entry.Tool = "generic-api-key"
	}
	return entry
}

// assertScannerCoverageCell checks that ValidateExceptions accepts function scope and rejects
// globs if and only if the HISS-20 coverage cell is decided by the HISS scanner.
func assertScannerCoverageCell(t *testing.T, ruleID string, cov hisscoverage.Coverage) {
	t.Helper()
	sample, ok := coverageLanguageTargets[cov.Language]
	if !ok {
		t.Fatalf("missing sample target for coverage language %q on %s", cov.Language, ruleID)
	}
	if cov.ReplayedHere() && cov.State.ClaimsDetection() {
		assertScannerDecidedCell(t, ruleID, cov.Language, sample)
		return
	}
	assertDelegatedCoverageCell(t, ruleID, cov.Language, sample)
}

// assertScannerDecidedCell verifies function-scope acceptance and glob refusal for a scanner cell.
func assertScannerDecidedCell(t *testing.T, ruleID, language string, sample languageTargetSample) {
	t.Helper()
	if err := config.ValidateExceptions([]config.Exception{buildScannerCellEntry(ruleID, sample.path, "", "targetFn")}, scannerRoutingToday); err != nil {
		t.Errorf("%s/%s is scanner-decided, yet function-scoped exception failed: %v", ruleID, language, err)
	}
	globErr := config.ValidateExceptions([]config.Exception{buildScannerCellEntry(ruleID, "", sample.glob, "")}, scannerRoutingToday)
	if globErr == nil || !strings.Contains(globErr.Error(), "must name one file by path, not a glob") {
		t.Errorf("%s/%s scanner cell accepted a glob target: %v", ruleID, language, globErr)
	}
}

// assertDelegatedCoverageCell verifies that non-scanner coverage cells reject function scope.
func assertDelegatedCoverageCell(t *testing.T, ruleID, language string, sample languageTargetSample) {
	t.Helper()
	if err := config.ValidateExceptions([]config.Exception{buildScannerCellEntry(ruleID, sample.path, "", "targetFn")}, scannerRoutingToday); err == nil {
		t.Errorf("%s/%s is not scanner-decided, yet function-scoped exception passed", ruleID, language)
	}
	fnPath := sample.path
	if ruleID == config.ExceptionRuleBuildWarnings || ruleID == config.ExceptionRuleWorkflowTriggers {
		fnPath = ".github/workflows/ci.yml"
	}
	targetErr := config.ValidateExceptions([]config.Exception{buildScannerCellEntry(ruleID, fnPath, "", "targetFn")}, scannerRoutingToday)
	if targetErr == nil || !strings.Contains(targetErr.Error(), "function is only valid for a HISS scanner rule") {
		t.Errorf("%s/%s function-scope refusal = %v, want HISS scanner rule refusal", ruleID, language, targetErr)
	}
}

// TestValidateExceptions_ScannerLanguageCellsMatchCoverage verifies every HISS-20 coverage cell
// and unlisted non-scanner cell against config.ValidateExceptions.
func TestValidateExceptions_ScannerLanguageCellsMatchCoverage(t *testing.T) {
	cat, err := hisscoverage.LoadCatalog(t.Context(), filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("load coverage catalog: %v", err)
	}
	for i := 0; i < len(cat.Rules); i++ {
		rule := cat.Rules[i]
		for j := 0; j < len(rule.Coverage); j++ {
			assertScannerCoverageCell(t, rule.ID, rule.Coverage[j])
		}
	}
	nonScannerCells := [][2]string{
		{"HISS-07", "src/sample.c"},
		{"HISS-08", "src/sample.rs"},
		{"HISS-08", "units/sample.service"},
		{"HISS-01", "units/sample.service"},
		{"HISS-01", "roles/app/tasks/main.yml"},
		{"HISS-02", "roles/app/tasks/main.yml"},
		{"HISS-04", "units/sample.service"},
		{"HISS-04", "src/Main.java"},
	}
	for i := 0; i < len(nonScannerCells); i++ {
		pair := nonScannerCells[i]
		cellErr := config.ValidateExceptions([]config.Exception{buildScannerCellEntry(pair[0], pair[1], "", "targetFn")}, scannerRoutingToday)
		if cellErr == nil || !strings.Contains(cellErr.Error(), "function is only valid for a HISS scanner rule") {
			t.Errorf("%s on %s must reject function scope, got: %v", pair[0], pair[1], cellErr)
		}
	}
}

// TestValidateExceptions_HISS04FunctionAndDelegatedDeciders covers HISS-04 function exceptions,
// Rust HISS-07 exceptions, and explicit tool delegation to non-scanner deciders.
func TestValidateExceptions_HISS04FunctionAndDelegatedDeciders(t *testing.T) {
	hiss04Fn := buildScannerCellEntry("HISS-04", "internal/foo.go", "", "BigSwitch")
	if err := config.ValidateExceptions([]config.Exception{hiss04Fn}, scannerRoutingToday); err != nil {
		t.Fatalf("HISS-04 function-scoped Go exception refused: %v", err)
	}
	rust07 := buildScannerCellEntry("HISS-07", "src/lib.rs", "", "")
	rust07Fn := buildScannerCellEntry("HISS-07", "src/lib.rs", "", "parse_header")
	if err := config.ValidateExceptions([]config.Exception{rust07, rust07Fn}, scannerRoutingToday); err != nil {
		t.Fatalf("Rust HISS-07 exceptions refused: %v", err)
	}
	delegatedLint := buildScannerCellEntry("HISS-04", "internal/foo.go", "", "")
	delegatedLint.Tool = "golangci-lint"
	delegatedSemgrep := buildScannerCellEntry("HISS-08", "pkg/eval.py", "", "")
	delegatedSemgrep.Tool = "semgrep"
	delegatedRustGlob := buildScannerCellEntry("HISS-08", "", "src/**/*.rs", "")
	if err := config.ValidateExceptions([]config.Exception{delegatedLint, delegatedSemgrep, delegatedRustGlob}, scannerRoutingToday); err != nil {
		t.Fatalf("delegated non-scanner exceptions refused: %v", err)
	}
	delegatedWithFn := delegatedLint
	delegatedWithFn.Function = "BigSwitch"
	if err := config.ValidateExceptions([]config.Exception{delegatedWithFn}, scannerRoutingToday); err == nil {
		t.Fatal("delegated tool entry with function scope must be refused")
	}
	selfTool := delegatedLint
	selfTool.Tool = "hiss"
	if err := config.ValidateExceptions([]config.Exception{selfTool}, scannerRoutingToday); err == nil {
		t.Fatal("setting tool: hiss on a scanner exception must be refused")
	}
}

// TestValidateExceptions_Control_HISS02FunctionScope is the passing control case holding both
// before and after typed scanner routing.
func TestValidateExceptions_Control_HISS02FunctionScope(t *testing.T) {
	valid := buildScannerCellEntry("HISS-02", "src/browser.go", "", "NewBrowser")
	if err := config.ValidateExceptions([]config.Exception{valid}, scannerRoutingToday); err != nil {
		t.Fatalf("control HISS-02 function-scoped exception refused: %v", err)
	}
	invalid := buildScannerCellEntry(config.ExceptionRuleBuildWarnings, ".github/workflows/ci.yml", "", "NewBrowser")
	if err := config.ValidateExceptions([]config.Exception{invalid}, scannerRoutingToday); err == nil {
		t.Fatal("control HISS-10 function-scoped exception accepted")
	}
}

// TestValidateExceptions_AmbiguousScannerGlob checks mixed-language globs, explicit
// delegation, fixed-language targets and directory patterns that reach workflow YAML.
func TestValidateExceptions_AmbiguousScannerGlob(t *testing.T) {
	cases := []struct {
		rule, path, glob, tool, problem string
	}{
		{"HISS-04", "", "src/*", "", `rule HISS-04 glob "src/*" has an ambiguous language`},
		{"HISS-09", "", "src/*", "", "delegate with tool"},
		{"HISS-04", "", "src/*.[gr]*", "", "delegate with tool"},
		{"HISS-04", "", "src/*", "golangci-lint", ""},
		{"HISS-04", "src/main.go", "", "", ""},
		{"HISS-04", "", "src/*.java", "", ""},
		{"HISS-08", "", "src/**/*.rs", "", ""},
		{"HISS-04", "", "**/*.yaml", "", "must name one file by path"},
		{"HISS-04", "", "src/**/*.yaml", "", ""},
	}
	for _, tc := range cases {
		entry := buildScannerCellEntry(tc.rule, tc.path, tc.glob, "")
		entry.Tool = tc.tool
		err := config.ValidateExceptions([]config.Exception{entry}, scannerRoutingToday)
		if tc.problem == "" {
			if err != nil {
				t.Errorf("%s %s (tool %q): %v", tc.rule, entry.Target(), tc.tool, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.problem) {
			t.Errorf("%s %s: got %v, want %q", tc.rule, tc.glob, err, tc.problem)
		}
	}
}
