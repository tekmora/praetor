// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"strings"
	"testing"
)

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
		{"opaque action", "      - uses: example/action@v1\n" + test, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := workflowTimeouts("ci.yml", []byte(header+tc.body))
			if len(findings) != 0 || tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("workflowTimeouts = %v, %v; want error containing %q (empty means pass)", findings, err, tc.want)
			}
		})
	}
}

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
