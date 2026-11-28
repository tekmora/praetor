// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/testsupport"
)

// These fixtures and TestStopInflight use only baseline symbols so the judge can replay the same test file on the parent.
const (
	unitLaunch = `{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","id":"launch","input":{"command":"systemd-run --user --unit=judge /bin/true"}}]}}`
	waitLaunch = `{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","id":"call-2","input":{"command":"wait-for-judge","run_in_background":true}}]}}`
	waitResult = `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"call-2","content":"Command running in background with ID: bg-7. Output written to fixture."}]},"toolUseResult":{"backgroundTaskId":"bg-7"}}`
	waitDone   = `{"type":"user","origin":{"kind":"task-notification"},"message":{"content":"<task-notification>\n<task-id>bg-7</task-id>\n<status>completed</status>\n</task-notification>"}}`
)

const unitStatusStub = `package main

import (
	"fmt"
	"os"
	"slices"
)

func main() {
	if !slices.Equal(os.Args[1:], []string{"--user", "is-active", "--", "judge"}) {
		os.Exit(1)
	}
	state := os.Getenv("PRAETOR_TEST_UNIT_STATE")
	fmt.Println(state)
	if state == "inactive" {
		os.Exit(3)
	}
}
`

// inflightFixture writes only the supplied synthetic JSONL into a private fixture directory.
func inflightFixture(t *testing.T, rows ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestStopInflight replays native Stop events against a clean checkpoint and a fixture systemctl.
func TestStopInflight(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd user unit fixture exercises the Linux stop path")
	}
	root := syncedRepository(t)
	_, getenv := buildStub(t, "python3")
	stubStdout(t, cleanReport)
	bin := t.TempDir()
	testsupport.BuildExecutable(t, bin, "systemctl", unitStatusStub)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	space := strings.Replace(unitLaunch, "--unit=judge", "--unit judge", 1)
	cases := []struct {
		name   string
		rows   []string
		state  string
		repeat bool
		exit   int
		text   string
	}{
		{"a-unwatched", []string{unitLaunch}, "active", false, 2, "judge"},
		{"b-pending", []string{space, waitLaunch, waitResult}, "active", false, 0, ""},
		{"c-completed", []string{space, waitLaunch, waitResult, waitDone}, "active", false, 2, "judge"},
		{"d-inactive", []string{unitLaunch}, "inactive", false, 0, ""},
		{"e-scope", []string{strings.Replace(space, "--user", "--user --scope", 1)}, "active", false, 0, ""},
		{"g-repeat", []string{unitLaunch}, "active", true, 0, "In-flight unit check skipped: stop_hook_active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PRAETOR_TEST_UNIT_STATE", tc.state)
			payload := commandPayload(t, map[string]any{
				"transcript_path": inflightFixture(t, tc.rows...), "stop_hook_active": tc.repeat, "last_assistant_message": "Done.",
			})
			response := Run(t.Context(), stopInvocation("claude", root, getenv, payload))
			stderr := string(response.Stderr)
			if response.ExitCode != tc.exit || !strings.Contains(stderr, tc.text) {
				t.Fatalf("got %s, want exit %d and %q", response, tc.exit, tc.text)
			}
			if tc.exit == 2 && !strings.Contains(strings.ToLower(stderr), "start one background wait on them, or stop them") {
				t.Errorf("missing recovery instruction: %s", stderr)
			}
			if tc.text == "" && strings.Contains(stderr, "In-flight unit check skipped") {
				t.Errorf("expected an evaluated allow: %s", stderr)
			}
		})
	}
}
