// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
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
		{"command-line override", write + "      - run: go test -timeout=30m ./...\n", ""},
		{"step override", write + test + "        env:\n          GOFLAGS: -timeout=30m\n", ""},
		{"dynamic payload", "      - run: echo \"$record\" >> \"$GITHUB_ENV\"\n" + test, "prior GITHUB_ENV write"},
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
			if len(findings) != 0 || tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("workflowTimeouts = %v, %v; want error containing %q (empty means pass)", findings, err, tc.want)
			}
			if tc.name == "same step and later step" && err != nil && strings.Contains(err.Error(), "prior shell text") {
				t.Fatalf("env-file data was treated as a current-shell mutation: %v", err)
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
