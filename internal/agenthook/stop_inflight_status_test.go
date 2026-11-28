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

// TestStopInflightSessionOwnership keeps another conversation's waiter out of the Stop decision.
func TestStopInflightSessionOwnership(t *testing.T) {
	tag := func(row, session string) string {
		return strings.Replace(row, "{", `{"sessionId":"`+session+`",`, 1)
	}
	rows := []string{tag(unitLaunch, "A"), tag(waitLaunch, "B"), tag(waitResult, "B")}
	checkInflightEvidence(t, "", rows, Allow, "session_id", 0)
	checkInflightEvidence(t, "A", rows, Deny, "", 1)
	checkInflightEvidence(t, "B", rows, Allow, "", 0)
}

// checkInflightEvidence checks both the verdict and whether the hook queried any fixture units.
func checkInflightEvidence(t *testing.T, session string, rows []string, want Outcome, note string, queries int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux status path only")
	}
	calls := 0
	status := func(_ context.Context, units []string) ([]string, error) {
		calls++
		states := make([]string, len(units))
		for i := range states {
			states[i] = "active"
		}
		return states, nil
	}
	stop := Canonical{ConversationID: session, TranscriptPath: inflightFixture(t, rows...)}
	got := evaluateStopInflight(t.Context(), "claude", stop, status)
	if got.Outcome != want || calls != queries || !strings.Contains(got.Notice, note) || (note == "" && got.Notice != "") {
		t.Errorf("got %+v after %d status calls, want outcome %d, note %q, calls %d", got, calls, want, note, queries)
	}
}

// TestStopInflightParseFailure refuses to evaluate a partial list of launches.
func TestStopInflightParseFailure(t *testing.T) {
	broken := strings.Replace(unitLaunch, "--unit=judge", "--unit='unfinished", 1)
	checkInflightEvidence(t, "", []string{unitLaunch, broken}, Allow, "unclosed quote", 0)
	rows := []string{unitLaunch}
	for i := 0; i < maxInflightUnits; i++ {
		rows = append(rows, strings.Replace(unitLaunch, "unit=judge", "unit="+strconv.Itoa(i), 1))
	}
	checkInflightEvidence(t, "", rows, Allow, "launch count exceeds", 0)
}

// TestStopInflightEmptyReceipt requires evidence before a pending waiter can be retired.
func TestStopInflightEmptyReceipt(t *testing.T) {
	empty := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"call-2"}]}}`
	checkInflightEvidence(t, "", []string{unitLaunch, waitLaunch, empty}, Allow, "no result evidence", 0)
	missingText := strings.Replace(empty, `"call-2"`, `"call-2","content":[{"type":"text"}]`, 1)
	checkInflightEvidence(t, "", []string{unitLaunch, waitLaunch, missingText}, Allow, "no result evidence", 0)
	synchronous := strings.Replace(empty, `"call-2"`, `"call-2","content":""`, 1)
	checkInflightEvidence(t, "", []string{unitLaunch, waitLaunch, synchronous}, Deny, "", 1)
	owned := strings.TrimSuffix(empty, "}") + `,"toolUseResult":{"backgroundTaskId":"bg-7"}}`
	checkInflightEvidence(t, "", []string{unitLaunch, waitLaunch, owned}, Allow, "", 0)
	conflict := strings.Replace(waitResult, `"backgroundTaskId":"bg-7"`, `"backgroundTaskId":"other"`, 1)
	checkInflightEvidence(t, "", []string{unitLaunch, waitLaunch, conflict}, Allow, "conflicting background task IDs", 0)
}

// TestStopInflightResultOwnership keeps the completed task for B from becoming a new waiter for A.
func TestStopInflightResultOwnership(t *testing.T) {
	callB := strings.Replace(waitLaunch, "call-2", "call-B", 1)
	receipt := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"call-2","content":"done"},{"type":"tool_result","tool_use_id":"call-B","content":"Command running in background with ID: bg-7."}]},"toolUseResult":{"backgroundTaskId":"bg-7"}}`
	rows := []string{unitLaunch, callB, waitDone, waitLaunch, receipt}
	checkInflightEvidence(t, "", rows, Deny, "", 1)
	rows[4] = strings.Replace(receipt, `,"content":"done"`, "", 1)
	checkInflightEvidence(t, "", rows, Allow, "no result evidence", 0)
}

// TestStopInflightConditionalLaunch requires a start receipt for the candidate unit from its own call.
func TestStopInflightConditionalLaunch(t *testing.T) {
	started := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"launch","content":"Running as unit: judge.service"}]}}`
	for _, prefix := range []string{"false && ", "true || ", "exit 1; ", `exit 1\n`} {
		launch := strings.Replace(unitLaunch, "systemd-run", prefix+"systemd-run", 1)
		checkInflightEvidence(t, "", []string{launch}, Allow, "judge", 0)
	}
	launch := strings.Replace(unitLaunch, "systemd-run", "prepare && systemd-run", 1)
	missing := strings.Replace(started, `,"content":"Running as unit: judge.service"`, "", 1)
	checkInflightEvidence(t, "", []string{launch, missing}, Allow, "judge", 0)
	malformed := strings.Replace(started, "judge.service", "judge.service; invocation ID: missing", 1)
	checkInflightEvidence(t, "", []string{launch, malformed}, Allow, "judge", 0)
	checkInflightEvidence(t, "", []string{launch, strings.Replace(started, "judge.service", "judge2.service", 1)}, Allow, "judge", 0)
	checkInflightEvidence(t, "", []string{launch, strings.Replace(started, `"launch"`, `"other"`, 1)}, Allow, "judge", 0)
	checkInflightEvidence(t, "", []string{launch, started}, Deny, "", 1)
	structured := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"launch"}]},"toolUseResult":{"stderr":"Running as unit: judge.service; invocation ID: 0123456789abcdef0123456789abcdef\n"}}`
	checkInflightEvidence(t, "", []string{launch, structured}, Deny, "", 1)
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
		if err := fixtureBashLaunch(t, &work, tc.command); err != nil || !slices.Equal(work.units, tc.units) {
			t.Errorf("%q: units %q, err %v, want %q", tc.command, work.units, err, tc.units)
		}
	}
}

// TestInflightUnitBound pins the last admitted unique name and rejects overflow without probing a truncated list.
func TestInflightUnitBound(t *testing.T) {
	var work inflightTranscript
	launch := func(name string) error {
		return fixtureBashLaunch(t, &work, "systemd-run --user --unit="+name+" true")
	}
	for i := 0; i < maxInflightUnits; i++ {
		if err := launch(strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := launch("0"); err != nil {
		t.Fatalf("repeated unit at limit: %v", err)
	}
	if err := launch("overflow"); err == nil || len(work.units) != maxInflightUnits {
		t.Fatalf("units %d, overflow error %v", len(work.units), err)
	}
}

// fixtureBashLaunch supplies the Bash identity used to match later tool results.
func fixtureBashLaunch(t *testing.T, work *inflightTranscript, command string) error {
	t.Helper()
	input := commandPayload(t, map[string]any{"command": command})
	return work.toolUse(inflightBlock{Type: "tool_use", Name: "Bash", ID: "launch", Input: input})
}
