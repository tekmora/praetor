// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/forge"
)

const jobTimeoutMissingFinding = "job-timeout: .github/workflows/job_missing.yml:3 job build: declares no timeout-minutes"

// runMissingTimeoutJobAudit writes a workflow whose build job sets no timeout-minutes and runs the CLI audit.
func runMissingTimeoutJobAudit(t *testing.T) (string, error) {
	t.Helper()
	f := newAuditFixture(t)
	writeFixtureFile(t, f.dir, ".github/workflows/job_missing.yml",
		"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 1\n")
	return f.audit(t, "--offline")
}

// assertJobTimeoutAuditWarns checks warn-period job-timeout output and a passing gate line.
func assertJobTimeoutAuditWarns(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("audit failed in the warn period: %v\nOutput: %s", err, out)
	}
	wantWarn := "[WARN] " + jobTimeoutMissingFinding + " (fails the audit from " + forge.JobTimeoutFailFrom.Format(time.DateOnly) + ")"
	lines := strings.Split(out, "\n")
	if !slices.Contains(lines, wantWarn) || !slices.Contains(lines, "[PASS] job-timeout") {
		t.Fatalf("audit output missing warning or gate pass:\n%s", out)
	}
}

// assertJobTimeoutAuditFails checks the CLI returns the original failure line on day.
func assertJobTimeoutAuditFails(t *testing.T, day time.Time, out string, err error) {
	t.Helper()
	if err == nil || !slices.Contains(strings.Split(err.Error(), "\n"), "[FAIL] "+jobTimeoutMissingFinding) {
		t.Fatalf("audit must fail with the finding on %s; err: %v\nOutput: %s",
			day.Format(time.DateOnly), err, out)
	}
}

// The CLI warns the day before the cutoff and fails on and after it. Each subtest
// pins the shared audit clock for its duration.
func TestAuditJobTimeouts_CLI_DatedSwitch(t *testing.T) {
	for _, tc := range [...]struct {
		name     string
		day      time.Time
		wantFail bool
	}{
		{"day_before", auditTodayBeforeJobTimeoutFail(), false},
		{"cutoff", forge.JobTimeoutFailFrom, true},
		{"day_after", forge.JobTimeoutFailFrom.AddDate(0, 0, 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinAuditToday(t, tc.day)
			out, err := runMissingTimeoutJobAudit(t)
			if tc.wantFail {
				assertJobTimeoutAuditFails(t, tc.day, out, err)
				return
			}
			assertJobTimeoutAuditWarns(t, out, err)
		})
	}
}
