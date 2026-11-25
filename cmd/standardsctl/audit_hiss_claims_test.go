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

	"github.com/cordanaLLM/praetor/internal/baseline"
	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

// contentClaimCase describes one file's HISS-07 findings and whether its waiver is stale.
type contentClaimCase struct {
	path, content string
	findings      int
	stale         bool
}

// TestAuditedInfractions_ContentClaims checks HISS-07 waivers against actual scan dispatch,
// including a claimed but clean playbook whose exception must still be reported as stale.
func TestAuditedInfractions_ContentClaims(t *testing.T) {
	cases := []contentClaimCase{
		{"compose.yaml", "services: {}\n", 0, false},
		{"NOTICE", "Plain text\n", 0, false},
		{"roles/app/tasks/main.yaml", "- name: ping\n  ping: {}\n  ignore_errors: true\n", 1, false},
		{"bin/run", "#!/bin/sh\necho ok\n", 1, false},
		{"site.yaml", "- hosts: all\n  tasks: []\n", 0, true},
		{ghworkflow.Dir + "/invalid.yml", "jobs: [\n", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) { tc.check(t, t.TempDir()) })
	}
}

// TestAuditedInfractions_WorkflowAdmission checks the same waiver at the last admitted
// workflow and again after one earlier workflow moves the target past the scanner's limit.
func TestAuditedInfractions_WorkflowAdmission(t *testing.T) {
	root := t.TempDir()
	const workflow = "name: CI\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "
	clean := workflow + "echo ok\n"
	for i := 1; i < ghworkflow.MaxFiles; i++ {
		writeFixtureFile(t, root, fmt.Sprintf("%s/fill-%03d.yml", ghworkflow.Dir, i), clean)
	}
	target := ghworkflow.Dir + "/target.yml"
	cleanCase := contentClaimCase{path: target, content: clean, stale: true}
	cleanCase.check(t, root)
	liveCase := contentClaimCase{path: target, content: workflow + "rm -f x || true\n", findings: 1}
	liveCase.check(t, root)
	writeFixtureFile(t, root, ghworkflow.Dir+"/extra.yml", clean)
	liveCase.findings = 0
	liveCase.check(t, root)
}

// check runs the scanner and the audit's waiver filter on the same repository snapshot.
func (tc contentClaimCase) check(t *testing.T, root string) {
	t.Helper()
	writeFixtureFile(t, root, tc.path, tc.content)
	rep, err := hiss.Scan(t.Context(), root, hiss.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Violations) != tc.findings {
		t.Fatalf("scan returned %+v, want %d findings", rep.Violations, tc.findings)
	}
	out, err := captureStdout(t, func() error {
		remaining, applyErr := auditedInfractions(rep, liveHISS07Options(tc.path, ""))
		if len(remaining) != 0 {
			t.Errorf("unexcused findings: %+v", remaining)
		}
		return applyErr
	})
	if tc.stale {
		mustErrContain(t, err, tc.path+") is unused")
	} else if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "[EXCUSED] HISS-07 "+tc.path+":"); got != tc.findings {
		t.Errorf("printed %d waivers, want %d: %s", got, tc.findings, out)
	}
}

// liveHISS07Options builds the audit policy for one live HISS-07 exception.
func liveHISS07Options(path, function string) *auditOptions {
	today := config.ExceptionDay(time.Now())
	entry := scannerTestEntry("HISS-07", path, function, today.AddDate(0, 0, 10).Format(config.ExceptionDateLayout))
	entry.Entered = today.Format(config.ExceptionDateLayout)
	manifest := &config.Manifest{Exceptions: []config.Exception{entry}}
	return &auditOptions{effective: &config.EffectivePolicy{Manifest: manifest}}
}

// TestHISSFindingDisplayPaths compares a waiver with a rejection in the same file, using
// native paths and the Windows spelling so the output regression is observable on Unix too.
func TestHISSFindingDisplayPaths(t *testing.T) {
	native := filepath.Join("src", "lib.rs")
	for _, path := range []string{native, `src\lib.rs`} {
		rep := &hiss.ScanReport{Violations: []hiss.InvariantViolation{
			{RuleID: "HISS-07", FilePath: native, LineNumber: 2, Symbol: "first"},
			{RuleID: "HISS-07", FilePath: path, LineNumber: 9, Symbol: "second"},
		}}
		var remaining []baseline.Infraction
		out, err := captureStdout(t, func() error {
			var applyErr error
			remaining, applyErr = auditedInfractions(rep, liveHISS07Options("src/lib.rs", "first"))
			return applyErr
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(remaining) != 1 || remaining[0].Symbol != "second" {
			t.Fatalf("unexcused findings: %+v", remaining)
		}
		result := baseline.EvaluateRatchet(&baseline.Baseline{}, remaining, nil)
		mustContain(t, result.Summary(), "[HISS-07] src/lib.rs:9")
		mustContain(t, out, "[EXCUSED] HISS-07 src/lib.rs:2")
	}
}

// TestPrintExcusedHISSFinding_WindowsPath checks the waiver printer with backslashes on any host.
func TestPrintExcusedHISSFinding_WindowsPath(t *testing.T) {
	finding := hiss.InvariantViolation{RuleID: "HISS-07", FilePath: `src\lib.rs`, LineNumber: 2}
	entry := scannerTestEntry("HISS-07", "src/lib.rs", "", "2026-11-20")
	out, err := captureStdout(t, func() error {
		printExcusedHISSFinding(finding, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "[EXCUSED] HISS-07 src/lib.rs:2")
}
