// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestStopInflightStatusFailure injects the two status failures without starting a command.
func TestStopInflightStatusFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux status path only")
	}
	stop := Canonical{TranscriptPath: inflightFixture(t, unitLaunch)}
	for _, failure := range []error{context.DeadlineExceeded, exec.ErrNotFound} {
		calls := 0
		status := func(ctx context.Context, units []string) ([]string, error) {
			calls++
			if _, ok := ctx.Deadline(); !ok || !slices.Equal(units, []string{"judge"}) {
				t.Fatalf("status needs deadline and one fixture unit, got %v", units)
			}
			return nil, failure
		}
		got := evaluateStopInflight(t.Context(), "claude", stop, status)
		if calls != 1 || got.Outcome != Allow || !strings.Contains(got.Notice, failure.Error()) ||
			!strings.Contains(got.Notice, "systemctl --user is-active") {
			t.Errorf("calls %d, failure %v, verdict %+v", calls, failure, got)
		}
	}
}

// TestStopInflightUnavailable distinguishes the platform, client and transcript skips without a runner.
func TestStopInflightUnavailable(t *testing.T) {
	skip := func(client, path, reason string) {
		t.Helper()
		verdict := evaluateStopInflight(t.Context(), client, Canonical{TranscriptPath: path}, nil)
		if verdict.Outcome != Allow || !strings.Contains(verdict.Notice, reason) {
			t.Errorf("%s: got %+v, want named allow containing %q", client, verdict, reason)
		}
	}
	skip("codex", "", "unsupported client codex")
	if runtime.GOOS != "linux" {
		skip("claude", "", runtime.GOOS)
		return
	}
	skip("claude", "", "missing transcript_path")
	skip("claude", filepath.Join(t.TempDir(), "absent.jsonl"), "read Claude transcript")
	skip("claude", inflightFixture(t, "{"), "decode Claude transcript row")
	oversized := inflightFixture(t)
	if err := os.Truncate(oversized, maxClaudeTranscriptBytes+1); err != nil {
		t.Fatal(err)
	}
	skip("claude", oversized, "exceeds")
}

// TestStopInflightBatch pins a single ordered status call, per-unit matching and the five-name display cap.
func TestStopInflightBatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux status path only")
	}
	names := []string{"one", "two", "three", "four", "five", "six", "seven", "eight"}
	rows := []string{strings.Replace(unitLaunch, "--unit=judge", "--unit=one", 1)}
	for _, name := range names {
		rows = append(rows, strings.Replace(unitLaunch, "--unit=judge", "--unit="+name, 1))
	}
	calls := 0
	status := func(_ context.Context, units []string) ([]string, error) {
		calls++
		if !slices.Equal(units, names) {
			t.Fatalf("status queried %q, want %q", units, names)
		}
		return []string{"inactive", "activating", "reloading", "failed", "active", "active", "active", "active"}, nil
	}
	verdict := evaluateStopInflight(t.Context(), "claude", Canonical{TranscriptPath: inflightFixture(t, rows...)}, status)
	if calls != 1 || verdict.Outcome != Deny || !strings.Contains(verdict.Reason, "two, three, five, six, seven.") ||
		strings.Contains(verdict.Reason, "eight") {
		t.Errorf("calls %d, verdict %+v", calls, verdict)
	}
}

// TestStopInflightNotifications checks chronological, ID-specific terminal statuses and the text receipt fallback.
func TestStopInflightNotifications(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux status path only")
	}
	result := strings.Replace(waitResult, `,"toolUseResult":{"backgroundTaskId":"bg-7"}`, "", 1)
	cases := []struct {
		name string
		rows []string
		want Outcome
	}{
		{"failed", []string{waitLaunch, result, strings.Replace(waitDone, "completed", "failed", 1)}, Deny},
		{"killed", []string{waitLaunch, result, strings.Replace(waitDone, "completed", "killed", 1)}, Deny},
		{"unrelated", []string{waitLaunch, result, strings.Replace(waitDone, "bg-7", "bg-other", 1)}, Allow},
		{"nonterminal", []string{waitLaunch, result, strings.Replace(waitDone, "completed", "running", 1)}, Allow},
		{"earlier", []string{waitDone, waitLaunch, result}, Allow},
		{"before-receipt", []string{waitLaunch, waitDone, result}, Deny},
		{"queued", []string{waitLaunch, result, `{"type":"queue-operation","operation":"enqueue","content":"<task-notification><task-id>bg-7</task-id><status>killed</status></task-notification>"}`}, Deny},
		{"sidechain", []string{strings.Replace(waitLaunch, `"type":"assistant"`, `"isSidechain":true,"type":"assistant"`, 1), result}, Deny},
	}
	for _, tc := range cases {
		stop := Canonical{TranscriptPath: inflightFixture(t, append([]string{unitLaunch}, tc.rows...)...)}
		status := func(context.Context, []string) ([]string, error) { return []string{"active"}, nil }
		got := evaluateStopInflight(t.Context(), "claude", stop, status)
		if got.Outcome != tc.want || got.Notice != "" {
			t.Errorf("%s: got %+v, want evaluated outcome %d", tc.name, got, tc.want)
		}
	}
}

// TestInflightLaunchOperands distinguishes wrapper options from child argv and quoted shell data.
func TestInflightLaunchOperands(t *testing.T) {
	for _, tc := range []struct {
		command string
		units   []string
	}{
		{"praetorctl admit -- systemd-run --user -p MemoryHigh=2G --unit 'judge' -- runner --scope", []string{"judge"}},
		{"echo 'systemd-run --user --unit=printed true' && systemd-run --unit=x --user true --unit=y", []string{"x"}},
		{"cat <<'END'\nsystemd-run --user --unit=fake true\nEND\nsystemd-run --user --unit='actual' true", []string{"actual"}},
		{"systemd-run --user --scope --unit=short true; systemd-run --unit=system true", nil},
	} {
		var work inflightTranscript
		if err := work.launches(tc.command); err != nil || !slices.Equal(work.units, tc.units) {
			t.Errorf("%q: units %q, err %v, want %q", tc.command, work.units, err, tc.units)
		}
	}
}

// TestInflightUnitBound pins the last admitted unique name and rejects overflow without probing a truncated list.
func TestInflightUnitBound(t *testing.T) {
	var work inflightTranscript
	for i := 0; i < maxInflightUnits; i++ {
		if err := work.addUnit([]string{"--user", "--unit", strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := work.addUnit([]string{"--user", "--unit=0"}); err != nil {
		t.Fatalf("repeated unit at limit: %v", err)
	}
	if err := work.addUnit([]string{"--user", "--unit=overflow"}); err == nil || len(work.units) != maxInflightUnits {
		t.Fatalf("units %d, overflow error %v", len(work.units), err)
	}
}
