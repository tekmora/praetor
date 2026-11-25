// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

// scannerExceptionsToday is the fixed calendar day used by HISS scanner exception unit tests.
var scannerExceptionsToday = time.Date(2026, time.November, 10, 0, 0, 0, 0, time.UTC)

// scannerTestEntry builds a categorized Exception entry for HISS scanner exception tests.
func scannerTestEntry(rule, path, fn, expires string) config.Exception {
	return config.Exception{
		Rule:     rule,
		Path:     path,
		Function: fn,
		Category: "C",
		Entered:  "2026-11-10",
		Expires:  expires,
		Reason:   "tracked scanner debt",
	}
}

// longGoFunctionSource renders a valid Go function with bodyLines statements for HISS-04 tests.
func longGoFunctionSource(pkgHeader, name string, bodyLines int) string {
	var b strings.Builder
	b.WriteString(pkgHeader)
	fmt.Fprintf(&b, "func %s(x int) int {\n", name)
	for i := 0; i < bodyLines && i < 256; i++ {
		b.WriteString("\tx++\n")
	}
	b.WriteString("\treturn x\n}\n")
	return b.String()
}

// TestApplyHISSExceptions_HISS04FunctionScopeOnlyExcusesTarget verifies that a live function-scoped
// HISS-04 exception waives only its own file and function, leaving sibling functions and other
// files unexcused.
func TestApplyHISSExceptions_HISS04FunctionScopeOnlyExcusesTarget(t *testing.T) {
	violations := []hiss.InvariantViolation{
		{RuleID: "HISS-04", FilePath: "sizer.go", LineNumber: 3, Symbol: "Oversized", Anchor: "fn:Oversized"},
		{RuleID: "HISS-04", FilePath: "sizer.go", LineNumber: 70, Symbol: "OtherOversized", Anchor: "fn:OtherOversized"},
		{RuleID: "HISS-04", FilePath: "other.go", LineNumber: 3, Symbol: "Oversized", Anchor: "fn:Oversized"},
	}
	entries := []config.Exception{scannerTestEntry("HISS-04", "sizer.go", "Oversized", "2026-11-20")}
	var remaining []hiss.InvariantViolation
	out, err := captureStdout(t, func() error {
		var applyErr error
		remaining, applyErr = applyHISSExceptions(violations, entries, scannerExceptionsToday)
		return applyErr
	})
	if err != nil {
		t.Fatalf("applyHISSExceptions failed: %v", err)
	}
	mustContain(t, out, "[EXCUSED] HISS-04 sizer.go:3 function Oversized: tracked scanner debt; exception until 2026-11-20.")
	if len(remaining) != 2 || remaining[0].Symbol != "OtherOversized" || remaining[1].FilePath != "other.go" {
		t.Fatalf("remaining = %+v, want OtherOversized in sizer.go and Oversized in other.go", remaining)
	}
}

// TestApplyHISSExceptions_RustHISS07TargetAndFunctionScope scans real Rust sources and verifies
// both file-scoped and function-scoped HISS-07 exceptions apply only to their declared target.
func TestApplyHISSExceptions_RustHISS07TargetAndFunctionScope(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "src/lib.rs", "pub fn parse_header(s: &str) -> usize {\n    s.parse::<usize>().unwrap()\n}\npub fn parse_body(s: &str) -> usize {\n    s.parse::<usize>().expect(\"n\")\n}\n")
	writeFixtureFile(t, dir, "src/other.rs", "pub fn load() -> u8 {\n    None.unwrap()\n}\n")
	rep, err := hiss.Scan(t.Context(), dir, hiss.ScanOptions{})
	if err != nil || len(rep.Violations) != 3 {
		t.Fatalf("scan Rust fixture: err=%v violations=%+v", err, rep.Violations)
	}
	var byPath, byFunc []hiss.InvariantViolation
	if _, err := captureStdout(t, func() error {
		var applyErr error
		byPath, applyErr = applyHISSExceptions(rep.Violations, []config.Exception{scannerTestEntry("HISS-07", "src/lib.rs", "", "2026-11-20")}, scannerExceptionsToday)
		return applyErr
	}); err != nil || len(byPath) != 1 || filepath.ToSlash(byPath[0].FilePath) != "src/other.rs" {
		t.Fatalf("file-scoped Rust HISS-07: err=%v remaining=%+v", err, byPath)
	}
	if _, err := captureStdout(t, func() error {
		var applyErr error
		byFunc, applyErr = applyHISSExceptions(rep.Violations, []config.Exception{scannerTestEntry("HISS-07", "src/lib.rs", "parse_header", "2026-11-20")}, scannerExceptionsToday)
		return applyErr
	}); err != nil || len(byFunc) != 2 {
		t.Fatalf("function-scoped Rust HISS-07: err=%v remaining=%+v", err, byFunc)
	}
}

// TestApplyHISSExceptions_ExpiredAndUnusedScannerEntriesFail verifies that unused HISS-04 and Rust
// HISS-07 entries fail as stale, while expired entries leave violations unexcused and fail expiry.
func TestApplyHISSExceptions_ExpiredAndUnusedScannerEntriesFail(t *testing.T) {
	_, err := applyHISSExceptions(nil, []config.Exception{scannerTestEntry("HISS-04", "sizer.go", "Gone", "2026-11-20")}, scannerExceptionsToday)
	mustErrContain(t, err, "HISS exception (rule HISS-04, sizer.go) is unused")

	_, err = applyHISSExceptions(nil, []config.Exception{scannerTestEntry("HISS-07", "src/clean.rs", "", "2026-11-20")}, scannerExceptionsToday)
	mustErrContain(t, err, "HISS exception (rule HISS-07, src/clean.rs) is unused")

	violations := []hiss.InvariantViolation{
		{RuleID: "HISS-04", FilePath: "sizer.go", LineNumber: 3, Symbol: "Oversized", Anchor: "fn:Oversized"},
		{RuleID: "HISS-07", FilePath: "src/lib.rs", LineNumber: 2, Anchor: "fn:parse_header"},
	}
	expired := []config.Exception{
		{Rule: "HISS-04", Path: "sizer.go", Function: "Oversized", Category: "C", Entered: "2026-10-25", Expires: "2026-11-04", Reason: "expired HISS-04"},
		{Rule: "HISS-07", Path: "src/lib.rs", Category: "C", Entered: "2026-10-25", Expires: "2026-11-04", Reason: "expired Rust HISS-07"},
	}
	remaining, err := applyHISSExceptions(violations, expired, scannerExceptionsToday)
	if err != nil || len(remaining) != 2 {
		t.Fatalf("expired entries must mark used without excusing findings: err=%v remaining=%+v", err, remaining)
	}
	mustErrContain(t, auditExpiredExceptions(&config.Manifest{Exceptions: expired}, scannerExceptionsToday), "expired on 2026-11-04")

	live := []config.Exception{scannerTestEntry("HISS-04", "sizer.go", "Oversized", "2026-11-20"), scannerTestEntry("HISS-07", "src/lib.rs", "", "2026-11-20")}
	if _, err := captureStdout(t, func() error {
		var applyErr error
		remaining, applyErr = applyHISSExceptions(violations, live, scannerExceptionsToday)
		return applyErr
	}); err != nil || len(remaining) != 0 {
		t.Fatalf("renewed entries must excuse both findings: err=%v remaining=%+v", err, remaining)
	}
}

// TestApplyHISSExceptions_DelegatedEntriesSkipScannerRoute verifies that exceptions targeting
// non-scanner language cells or naming an explicit delegating tool are neither rejected as unused
// by applyHISSExceptions nor allowed to waive HISS scanner findings.
func TestApplyHISSExceptions_DelegatedEntriesSkipScannerRoute(t *testing.T) {
	delegatedGo := scannerTestEntry("HISS-04", "sizer.go", "", "2026-11-20")
	delegatedGo.Tool = "golangci-lint"
	delegatedPy := scannerTestEntry("HISS-08", "script.py", "", "2026-11-20")
	delegatedPy.Tool = "semgrep"
	entries := []config.Exception{
		scannerTestEntry("HISS-08", "src/lib.rs", "", "2026-11-20"),
		scannerTestEntry("HISS-07", "src/native.c", "", "2026-11-20"),
		delegatedGo,
		delegatedPy,
	}
	if err := config.ValidateExceptions(entries, scannerExceptionsToday); err != nil {
		t.Fatalf("delegated entries failed validation: %v", err)
	}
	if remaining, err := applyHISSExceptions(nil, entries, scannerExceptionsToday); err != nil || len(remaining) != 0 {
		t.Fatalf("delegated entries judged by scanner route: err=%v remaining=%+v", err, remaining)
	}
	violations := []hiss.InvariantViolation{{RuleID: "HISS-04", FilePath: "sizer.go", LineNumber: 3, Symbol: "Oversized", Anchor: "fn:Oversized"}}
	remaining, err := applyHISSExceptions(violations, entries, scannerExceptionsToday)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("tool-delegated HISS-04 entry must not excuse HISS scanner LOC finding: err=%v remaining=%+v", err, remaining)
	}
}

// TestAudit_HISSScannerExceptions_EndToEnd exercises full praetorctl audit runs for a touched
// Go HISS-04 function exception and a touched Rust HISS-07 exception.
func TestAudit_HISSScannerExceptions_EndToEnd(t *testing.T) {
	f := newAuditFixture(t)
	today := config.ExceptionDay(time.Now())
	entered := today.Format(config.ExceptionDateLayout)
	expires := today.AddDate(0, 0, 10).Format(config.ExceptionDateLayout)
	goSrc := longGoFunctionSource("package p\n\n", "Oversized", 60)
	rustSrc := "pub fn parse_header(s: &str) -> usize {\n    s.parse::<usize>().unwrap()\n}\n"
	writeFixtureFile(t, f.dir, "sizer.go", goSrc)
	writeFixtureFile(t, f.dir, "src/lib.rs", rustSrc)
	rep, err := hiss.Scan(t.Context(), f.dir, hiss.ScanOptions{})
	if err != nil || len(rep.Violations) != 2 {
		t.Fatalf("scan fixture: err=%v violations=%+v", err, rep.Violations)
	}
	f.writeBaseline(t, hiss.ConvertToBaseline(rep.Violations), "")
	gitCommitAll(t, f.dir, f.gitEnv, "baseline HISS-04 and Rust HISS-07")
	writeFixtureFile(t, f.dir, "sizer.go", goSrc+"// touched\n")
	writeFixtureFile(t, f.dir, "src/lib.rs", rustSrc+"// touched\n")

	_, err = f.audit(t, "--touched=sizer.go,src/lib.rs")
	mustErrContain(t, err, "touched file must be clean")

	manifest := fixtureManifest("acme", "widgets", false) + fmt.Sprintf(
		"exceptions:\n  - rule: HISS-04\n    path: sizer.go\n    function: Oversized\n    category: C\n    entered: %q\n    expires: %q\n    reason: split scheduled\n"+
			"  - rule: HISS-07\n    path: src/lib.rs\n    category: C\n    entered: %q\n    expires: %q\n    reason: error type migration\n",
		entered, expires, entered, expires)
	writeFixtureFile(t, f.dir, ".standards.yaml", manifest)
	out, err := f.audit(t, "--touched=sizer.go,src/lib.rs")
	if err != nil {
		t.Fatalf("live HISS-04 and Rust HISS-07 exceptions failed audit: %v\n%s", err, out)
	}
	mustContain(t, out, "[EXCUSED] HISS-04 sizer.go", "function Oversized", "[EXCUSED] HISS-07 src/lib.rs")
}

// TestApplyHISSExceptions_Control_HISS02AndWorkflowRule is the passing control case holding both
// before and after typed scanner routing.
func TestApplyHISSExceptions_Control_HISS02AndWorkflowRule(t *testing.T) {
	violations := []hiss.InvariantViolation{
		{RuleID: "HISS-02", FilePath: "browser.go", LineNumber: 4, Symbol: "NewBrowser", Anchor: "fn:NewBrowser"},
		{RuleID: "HISS-02", FilePath: "browser.go", LineNumber: 12, Symbol: "Other", Anchor: "fn:Other"},
	}
	entries := []config.Exception{
		scannerTestEntry("HISS-02", "browser.go", "NewBrowser", "2026-11-20"),
		scannerTestEntry(config.ExceptionRuleBuildWarnings, ".github/workflows/ci.yml", "", "2026-11-20"),
	}
	var remaining []hiss.InvariantViolation
	_, err := captureStdout(t, func() error {
		var applyErr error
		remaining, applyErr = applyHISSExceptions(violations, entries, scannerExceptionsToday)
		return applyErr
	})
	if err != nil || len(remaining) != 1 || remaining[0].Symbol != "Other" {
		t.Fatalf("control HISS-02 routing failed: err=%v remaining=%+v", err, remaining)
	}
}
