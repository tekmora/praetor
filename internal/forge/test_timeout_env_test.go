// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTimeoutWorkflowEnvWrites checks how environment-file writes affect later test invocations.
func TestTimeoutWorkflowEnvWrites(t *testing.T) {
	const header = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
	const write = "      - run: echo 'GOFLAGS=-timeout=0' >> \"$GITHUB_ENV\"\n"
	const test = "      - run: go test ./...\n"
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"later step", write + test, ":6 unverifiable test invocation: 0 disables the test deadline"},
		{"supported writer template", strings.Replace(write, "- run:", "- shell: bash -e {0}\n        run:", 1) + test, "0 disables the test deadline"},
		{"unsupported writer template", strings.Replace(write, "- run:", "- shell: bash -n {0}\n        run:", 1) + test, "prior GITHUB_ENV write"},
		{"command-line override", write + "      - run: go test -timeout=30m ./...\n", ""},
		{"step override", write + test + "        env:\n          GOFLAGS: -timeout=30m\n", ""},
		{"dynamic payload", "      - run: echo \"$record\" >> \"$GITHUB_ENV\"\n" + test, "prior GITHUB_ENV write"},
		{"guarded append", strings.ReplaceAll(strings.ReplaceAll(write, "$GITHUB_ENV", "${GITHUB_ENV:?}"), "-timeout=0", "-timeout=45m") + test, "prior GITHUB_ENV write"},
		{"different file", strings.ReplaceAll(write, "$GITHUB_ENV", "$GITHUB_OUTPUT") + test, ""},
		{"different record", strings.ReplaceAll(write, "GOFLAGS", "OTHER") + test, ""},
		{"runner path setup", "      - run: |\n          python3 -m venv \"$RUNNER_TEMP/praetor-hook-lint\"\n          echo \"PRAETOR_HOOK_LINT_BIN=$RUNNER_TEMP/praetor-hook-lint/bin\" >> \"$GITHUB_ENV\"\n" + test, ""},
		{"unrelated dynamic record", "      - run: echo \"OTHER=$record\" >> \"$GITHUB_ENV\"\n" + test, "prior GITHUB_ENV write"},
		{"last literal wins", "      - run: |\n          echo 'GOFLAGS=-timeout=0' >> \"$GITHUB_ENV\"\n          echo 'OTHER=ok' >> \"$GITHUB_ENV\"\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n" + test, ""},
		{"last unknown wins", "      - run: |\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n          echo \"$record\" >> \"$GITHUB_ENV\"\n" + test, "prior GITHUB_ENV write"},
		{"conditional command", "      - run: |\n          if test -f marker; then\n            echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n          fi\n" + test, "prior GITHUB_ENV write"},
		{"conditional step", strings.ReplaceAll(write, "      - run:", "      - if: inputs.configure\n        run:") + test, "prior GITHUB_ENV write"},
		{"different job", write + "  unrelated:\n    runs-on: ubuntu-latest\n    steps:\n" + test, ""},
		{"later write", test + write, ""},
		{"PowerShell later step", "      - shell: pwsh\n        run: Add-Content $env:GITHUB_ENV 'GOFLAGS=-timeout=0'\n" + test, "prior GITHUB_ENV write"},
		{"PowerShell append before Bash test", "      - shell: pwsh\n        run: |\n          \"GOFLAGS=-timeout=0\" >> $env:GITHUB_ENV\n      - shell: bash\n        run: go test ./...\n", "prior GITHUB_ENV write"},
		{"Windows PowerShell redirect before Bash test", "      - shell: powershell\n        run: |\n          \"GOFLAGS=-timeout=0\" > \"$ENV:github_env\"\n      - shell: bash\n        run: go test ./...\n", "prior GITHUB_ENV write"},
		{"PowerShell redirect to different file", "      - shell: pwsh\n        run: |\n          \"GOFLAGS=-timeout=0\" >> $env:GITHUB_OUTPUT\n" + test, ""},
		{"PowerShell different file", "      - shell: pwsh\n        run: Add-Content $env:GITHUB_OUTPUT 'GOFLAGS=-timeout=0'\n" + test, ""},
		{"PowerShell line comment", "      - shell: pwsh\n        run: \"# Add-Content $env:GITHUB_ENV 'GOFLAGS=-timeout=0'\"\n" + test, ""},
		{"multiline body is not an assignment", "      - run: |\n          echo 'OTHER<<END' >> \"$GITHUB_ENV\"\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n          echo 'END' >> \"$GITHUB_ENV\"\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n" + test, "prior GITHUB_ENV write"},
		{"new step has a fresh env file", "      - run: echo \"$record\" >> \"$GITHUB_ENV\"\n" + strings.ReplaceAll(write, "-timeout=0", "-timeout=30m") + test, ""},
		{"same step and later step", "      - run: |\n          echo 'GOFLAGS=-timeout=0' >> \"$GITHUB_ENV\"\n          go test ./...\n" + test, ":8 unverifiable test invocation: 0 disables the test deadline"},
		{"same step retains step environment", "      - env:\n          GOFLAGS: -timeout=0\n        run: |\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n          go test ./...\n", "0 disables the test deadline"},
		{"same step still detects shell mutation", "      - run: |\n          echo 'GOFLAGS=-timeout=30m' >> \"$GITHUB_ENV\"\n          export GOFLAGS=-timeout=0\n          go test ./...\n", "prior shell text"},
		{"opaque action", "      - uses: example/action@v1\n" + test, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := workflowTimeouts("ci.yml", []byte(header+tc.body))
			assertTimeoutEnvWriteResult(t, findings, err, tc.want)
			if tc.name == "same step and later step" {
				want := "[FAIL] " + testTimeoutGate + ": ci.yml" + tc.want
				if err == nil || err.Error() != want {
					t.Fatalf("workflowTimeouts error = %v; want exactly %q", err, want)
				}
			}
		})
	}
}

// assertTimeoutEnvWriteResult checks for no findings and the expected error, if any.
func assertTimeoutEnvWriteResult(t *testing.T, findings []string, err error, want string) {
	t.Helper()
	if len(findings) != 0 || want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
		t.Fatalf("workflowTimeouts = %v, %v; want error containing %q (empty means pass)", findings, err, want)
	}
}

func TestAuditTestTimeouts_WorkflowProofRegressions(t *testing.T) {
	const header = "name: Timeout regression\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
	const template = "      - shell: bash --noprofile --norc -e {0}\n"
	const bounded = "        run: go test -timeout=30m ./...\n"
	const long = "        run: go test -timeout=45m ./...\n"
	const write = "      - run: echo 'GOFLAGS=-timeout=45m' >> \"$GITHUB_ENV\"\n"
	const noFlag = "        run: go test ./...\n"
	for _, tc := range []struct{ name, steps, want string }{
		{"file template at bound", template + bounded, ""},
		{"file template measures long timeout", template + long, "45m, above the 30m bound"},
		{"no-exec template is not proof", "      - shell: bash -n {0}\n" + long, `unsupported shell template "bash -n {0}"`},
		{"success conjunction at bound", strings.Replace(write, "45m", "20m", 1) + "      - if: success() && true\n" + bounded, ""},
		{"plain success inherits long timeout", write + "      - if: success()\n" + noFlag, "45m, above the 30m bound"},
		{"success conjunction inherits long timeout", write + "      - if: success() && true\n" + noFlag, "45m, above the 30m bound"},
		{"success disjunction is not proof", write + "      - if: success() || true\n" + noFlag, "cannot verify inherited GOFLAGS from prior GITHUB_ENV write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, ".github", "workflows")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(header+tc.steps), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := AuditTestTimeouts(context.Background(), TestTimeoutOptions{Root: root})
			assertWorkflowProofResult(t, out, err, tc.want)
		})
	}
}

func assertWorkflowProofResult(t *testing.T, out string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil || out != "[PASS] test-timeout" {
			t.Fatalf("AuditTestTimeouts = %q, %v; want pass", out, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), ".github/workflows/ci.yml:") || !strings.Contains(err.Error(), want) {
		t.Fatalf("AuditTestTimeouts = %q, %v; want ci.yml diagnostic containing %q", out, err, want)
	}
}

func TestTimeoutWorkflowShellTemplates(t *testing.T) {
	const job = "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
	const steps = "    steps:\n"
	const long = "        run: go test -timeout=45m ./...\n"
	const boundedWithComment = "        run: |\n          # go test -timeout=45m ./...\n          go test -timeout=30m ./...\n"
	const jobNoExec = "    defaults:\n      run:\n        shell: bash -n {0}\n"
	const workflowNoExec = "defaults:\n  run:\n    shell: bash -n {0}\n"
	for _, tc := range []struct {
		name, workflow, finding, refusal string
	}{
		{"runner default", job + steps + "      - " + strings.TrimLeft(long, " "), "45m, above the 30m bound", ""},
		{"built-in step overrides no-exec job default", job + jobNoExec + steps + "      - shell: bash\n" + long, "45m, above the 30m bound", ""},
		{"canonical template checks code not comments", job + steps + "      - shell: bash --noprofile --norc -eo pipefail {0}\n" + boundedWithComment, "", ""},
		{"job template overrides no-exec workflow default", workflowNoExec + job + "    defaults:\n      run:\n        shell: sh -e {0}\n" + steps + "      - " + strings.TrimLeft(long, " "), "45m, above the 30m bound", ""},
		{"step no-exec template", job + steps + "      - shell: bash -n {0}\n" + long, "", `unsupported shell template "bash -n {0}"`},
		{"job no-exec template", job + jobNoExec + steps + "      - " + strings.TrimLeft(long, " "), "", `unsupported shell template "bash -n {0}"`},
		{"workflow no-exec template", workflowNoExec + job + steps + "      - " + strings.TrimLeft(long, " "), "", `unsupported shell template "bash -n {0}"`},
		{"command string instead of script file", job + steps + "      - shell: bash -c {0}\n" + long, "", `unsupported shell template "bash -c {0}"`},
		{"extra template arguments", job + steps + "      - shell: bash -e {0} extra\n" + long, "", `unsupported shell template "bash -e {0} extra"`},
		{"unsupported template without candidate", job + steps + "      - shell: bash -n {0}\n        run: echo ok\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := workflowTimeouts("ci.yml", []byte(tc.workflow))
			assertTimeoutFinding(t, findings, tc.finding)
			if tc.refusal == "" && err != nil || tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), "unverifiable test invocation") || !strings.Contains(err.Error(), tc.refusal)) {
				t.Fatalf("error = %v; want unverifiable invocation with reason %q (empty means no error)", err, tc.refusal)
			}
		})
	}
}

// assertTimeoutFinding checks for no findings when want is empty, or one finding containing want.
func assertTimeoutFinding(t *testing.T, findings []string, want string) {
	t.Helper()
	if want == "" && len(findings) != 0 || want != "" && (len(findings) != 1 || !strings.Contains(findings[0], want)) {
		t.Fatalf("findings = %v; want %q", findings, want)
	}
}

func TestTimeoutWorkflowRunnerEnvKeys(t *testing.T) {
	const job = "jobs:\n  test:\n    runs-on: "
	const jobEnv = "    env:\n      GOFLAGS: -timeout=30m\n"
	const test = "      - shell: bash\n        run: go test ./...\n"
	const stepLong = "        env:\n          goflags: -timeout=45m\n"
	const stepBounded = "        env:\n          GoFlags: -timeout=30m\n"
	const priorWrite = "      - shell: bash\n        run: echo 'GOFLAGS=-timeout=0' >> \"$GITHUB_ENV\"\n"
	for _, tc := range []struct {
		name, runner, workflowEnv, jobEnv, steps, finding, refusal string
	}{
		{"Windows step overrides job", "windows-latest", "", jobEnv, test + stepLong, "45m, above the 30m bound", ""},
		{"Linux step does not override job", "ubuntu-latest", "", jobEnv, test + stepLong, "", ""},
		{"Windows falls back to mixed-case workflow key", "windows-latest", "env:\n  GoFlags: -timeout=45m\n", "", test, "45m, above the 30m bound", ""},
		{"Windows step at bound overrides prior write", "windows-latest", "", jobEnv, priorWrite + test + stepBounded, "", ""},
		{"Linux uses prior write despite mixed-case step key", "ubuntu-latest", "", jobEnv, priorWrite + test + stepBounded, "", "0 disables the test deadline"},
		{"Windows empty step binding overrides prior write", "windows-latest", "", jobEnv, priorWrite + test + "        env:\n          goflags: ''\n", "", ""},
		{"Windows same-scope case collision is ambiguous", "windows-latest", "", jobEnv, test + stepLong + "          GOFLAGS: -timeout=30m\n", "", "unverifiable test invocation"},
		{"Linux same-scope case variants are distinct", "ubuntu-latest", "", jobEnv, test + stepLong + "          GOFLAGS: -timeout=30m\n", "", ""},
		{"Windows nonliteral step key does not fall through", "windows-latest", "", jobEnv, test + "        env:\n          goflags: ${{ vars.TEST_FLAGS }}\n", "", "unverifiable test invocation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.workflowEnv + job + tc.runner + "\n" + tc.jobEnv + "    steps:\n" + tc.steps
			findings, err := workflowTimeouts("ci.yml", []byte(data))
			assertTimeoutFinding(t, findings, tc.finding)
			if tc.refusal == "" && err != nil || tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), tc.refusal)) {
				t.Fatalf("error = %v; want %q (empty means no error)", err, tc.refusal)
			}
		})
	}
}

// TestTimeoutWorkflowGOFLAGSPrintf distinguishes read-only formatting from shell mutations of GOFLAGS.
func TestTimeoutWorkflowGOFLAGSPrintf(t *testing.T) {
	const header = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n"
	for _, tc := range []struct {
		name string
		line string
		fail bool
	}{
		{"read", `printf '%s\n' "$GOFLAGS"`, false},
		{"literal label", `printf 'GOFLAGS=%s\n' "${GOFLAGS}"`, false},
		{"write", `printf -v GOFLAGS '%s' '-timeout=0'`, true},
		{"assignment", `export GOFLAGS=-timeout=0`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := workflowTimeouts("ci.yml", []byte(header+"          "+tc.line+"\n          go test -timeout=30m ./...\n"))
			if len(findings) != 0 || (err != nil) != tc.fail || err != nil && !strings.Contains(err.Error(), "prior shell text") {
				t.Fatalf("workflowTimeouts = %v, %v; want prior shell text failure: %t", findings, err, tc.fail)
			}
		})
	}
}
