// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
)

var timeoutsToday = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const boundWorkflow = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n" +
	"    steps:\n      - run: go test -timeout 30m ./...\n"

const longWorkflow = "on: push\njobs:\n  test:\n    runs-on: windows-latest\n" +
	"    steps:\n      - run: go test -timeout 60m ./internal/adopt\n"

// Negative: a 60m timeout with no exceptions entry fails and names the workflow, the line and the value.
func TestAuditTestTimeouts_Negative_LongTimeoutWithoutEntry(t *testing.T) {
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"portability.yml": longWorkflow}))
	if err == nil || !strings.Contains(err.Error(), ".github/workflows/portability.yml:6") || !strings.Contains(err.Error(), "60m") {
		t.Fatalf("AuditTestTimeouts = %q, %v; want the 60m line refused", out, err)
	}
}

// timeoutEntry is a test-timeout exceptions entry for the workflow file name.
func timeoutEntry(name, expires string) config.Exception {
	return config.Exception{Rule: config.ExceptionRuleTestTimeout, Path: ".github/workflows/" + name,
		Reason: "category B: the Windows adopt tests run past the bound (#1381)", Expires: expires}
}

// Boundary: a live entry passes the workflow and names its reason and expiry.
func TestAuditTestTimeouts_Boundary_LiveEntryPasses(t *testing.T) {
	root := triggerRepository(t, map[string]string{"portability.yml": longWorkflow})
	out, err := auditTimeouts(t, root, timeoutEntry("portability.yml", "2026-10-18"))
	if err != nil || !strings.Contains(out, "until 2026-10-18") || !strings.Contains(out, "#1381") {
		t.Fatalf("live entry: %q, %v; want the workflow passed with reason and expiry", out, err)
	}
}

// Negative: an expired entry excuses nothing; the failure names the expiry.
func TestAuditTestTimeouts_Negative_ExpiredEntryFails(t *testing.T) {
	root := triggerRepository(t, map[string]string{"portability.yml": longWorkflow})
	_, err := auditTimeouts(t, root, timeoutEntry("portability.yml", "2026-10-14"))
	if err == nil || !strings.Contains(err.Error(), "expired 2026-10-14") {
		t.Fatalf("expired entry: err = %v; want the expiry named", err)
	}
}

// Negative: an entry for a workflow within the bound excuses nothing and fails, so the entry goes
// once the timeout is back at the bound.
func TestAuditTestTimeouts_Negative_StaleEntryFails(t *testing.T) {
	root := triggerRepository(t, map[string]string{"ci.yml": boundWorkflow})
	_, err := auditTimeouts(t, root, timeoutEntry("ci.yml", "2026-10-18"))
	if err == nil || !strings.Contains(err.Error(), "excuses nothing") {
		t.Fatalf("stale entry: err = %v; want it refused", err)
	}
}

func auditTimeouts(t *testing.T, root string, entries ...config.Exception) (string, error) {
	t.Helper()
	return AuditTestTimeouts(t.Context(), TestTimeoutOptions{Root: root, Exceptions: entries, Today: timeoutsToday})
}

// Positive: a workflow within the bound passes without an entry.
func TestAuditTestTimeouts_Positive_WithinTheBound(t *testing.T) {
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": boundWorkflow}))
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("AuditTestTimeouts = %q, %v; want a pass", out, err)
	}
}

// Positive: a step with docker memory limits is ignored even when --stop-timeout is present.
func TestAuditTestTimeouts_Positive_DockerMemoryIgnored(t *testing.T) {
	wf := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run --memory 64m --memory-swap 64m --stop-timeout 5 image\n      - run: go test ./...\n"
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err != nil {
		t.Fatalf("AuditTestTimeouts = %q, %v; want docker memory ignored", out, err)
	}
}

// Negative: go test with timeouts above the bound are flagged, including combinations like 1h5m.
func TestAuditTestTimeouts_Negative_GoTestLongTimeouts(t *testing.T) {
	wf1 := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test -timeout 64m ./...\n"
	_, err1 := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf1}))
	if err1 == nil || !strings.Contains(err1.Error(), "64m") {
		t.Fatalf("err1 = %v; want 64m flagged", err1)
	}

	wf2 := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test ./... -timeout=1h5m\n"
	_, err2 := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf2}))
	if err2 == nil || !strings.Contains(err2.Error(), "1h5m") {
		t.Fatalf("err2 = %v; want 1h5m flagged", err2)
	}
}

// Boundary: go test with exactly 30m timeout passes.
func TestAuditTestTimeouts_Boundary_GoTestBoundPasses(t *testing.T) {
	wf := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test -timeout 30m ./...\n"
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("AuditTestTimeouts = %q, %v; want 30m to pass", out, err)
	}
}

// Boundary: a job's timeout-minutes is not this gate's subject (decision
// engine-timeout-audit-scope-20261018): 45 passes, as on the gate before the fix.
func TestAuditTestTimeouts_TimeoutMinutesNotJudged(t *testing.T) {
	wfLong := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 45\n    steps:\n      - run: go test ./...\n"
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wfLong}))
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("AuditTestTimeouts = %q, %v; want timeout-minutes: 45 left to a job-timeout gate", out, err)
	}
}

// Negative: an unparsable duration such as -timeout 5x is reported as unreadable.
func TestAuditTestTimeouts_Negative_UnreadableTimeout(t *testing.T) {
	wf := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test -timeout 5x ./...\n"
	_, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err == nil || !strings.Contains(err.Error(), "unreadable") || !strings.Contains(err.Error(), "5x") {
		t.Fatalf("err = %v; want unreadable timeout 5x reported", err)
	}
}

// reusableTimeoutWorkflow is a reusable workflow whose go test takes its timeout from an input,
// as golusoris's ci-go.yml does; inputBlock declares the input (or nothing).
func reusableTimeoutWorkflow(inputBlock string) string {
	return "on:\n  workflow_call:\n    inputs:\n" + inputBlock +
		"jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: go test -race -timeout=${{ inputs.test-timeout }} ./...\n"
}

// Positive: -timeout=${{ inputs.X }} reads the workflow_call default; 10m is within the bound.
func TestAuditTestTimeouts_Positive_InputDefaultWithinBound(t *testing.T) {
	wf := reusableTimeoutWorkflow("      test-timeout:\n        type: string\n        default: 10m\n")
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci-go.yml": wf}))
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("AuditTestTimeouts = %q, %v; want the 10m default to pass", out, err)
	}
}

// Negative: a default above the bound fails, naming the input and its default.
func TestAuditTestTimeouts_Negative_InputDefaultAboveBound(t *testing.T) {
	wf := reusableTimeoutWorkflow("      test-timeout:\n        type: string\n        default: 45m\n")
	_, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci-go.yml": wf}))
	if err == nil || !strings.Contains(err.Error(), "inputs.test-timeout") || !strings.Contains(err.Error(), "default 45m") ||
		!strings.Contains(err.Error(), "above the 30m bound") {
		t.Fatalf("err = %v; want the 45m default above the bound", err)
	}
}

// Boundary: an input without a default, or one the workflow does not declare, stays unreadable.
func TestAuditTestTimeouts_Boundary_InputWithoutDefaultUnreadable(t *testing.T) {
	for name, block := range map[string]string{
		"no default": "      test-timeout:\n        type: string\n        required: true\n",
		"undeclared": "      other:\n        type: string\n        default: 5m\n",
		"unparsable": "      test-timeout:\n        type: string\n        default: soon\n",
	} {
		_, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci-go.yml": reusableTimeoutWorkflow(block)}))
		if err == nil || !strings.Contains(err.Error(), "unreadable") || !strings.Contains(err.Error(), "inputs.test-timeout") {
			t.Fatalf("%s: err = %v; want an unreadable timeout naming the input", name, err)
		}
	}
	wf := reusableTimeoutWorkflow("      test-timeout:\n        type: string\n        default: 30m\n")
	if out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci-go.yml": wf})); err != nil {
		t.Fatalf("default at the bound = %q, %v; want a pass", out, err)
	}
}

// Makefile recipes obey the workflow bound, including the GO_TEST sandbox wrapper.
func TestAuditTestTimeouts_Makefile(t *testing.T) {
	entry := config.Exception{Rule: config.ExceptionRuleTestTimeout, Path: "Makefile",
		Category: "C", Entered: "2026-10-15", Expires: "2026-10-25", Reason: "category C: adopt speedup pending (#1381)"}
	expired := entry
	expired.Expires = "2026-10-14"
	for _, tc := range []struct {
		name    string
		command string
		entries []config.Exception
		wantErr string
		wantOut string
	}{
		{"no entry", "go test -race -timeout 45m ./internal/adopt/", nil, "Makefile:2 sets 45m", ""},
		{"wrapper without entry", "$(GO_TEST) -race -timeout 45m ./internal/adopt/", nil, "Makefile:2 sets 45m", ""},
		{"live entry", "$(GO_TEST) -race -timeout 45m ./internal/adopt/", []config.Exception{entry}, "", "Makefile excepted until 2026-10-25"},
		{"expired entry", "$(GO_TEST) -race -timeout 45m ./internal/adopt/", []config.Exception{expired}, "Makefile expired 2026-10-14", ""},
		{"boundary", "$(GO_TEST) -race -timeout 30m ./...", nil, "", "[PASS] test-timeout"},
		{"continued without entry", "$(GO_TEST) -v -race \\\n  -timeout 45m ./internal/adopt/", nil, "Makefile:2 sets 45m", ""},
		{"continued live entry", "$(GO_TEST) -v -race \\\n  -timeout 45m ./internal/adopt/", []config.Exception{entry}, "", "Makefile excepted until 2026-10-25"},
		{"continued boundary", "$(GO_TEST) -v -race \\\n  -timeout 30m ./...", nil, "", "[PASS] test-timeout"},
		{"stale entry", "$(GO_TEST) -race -timeout 30m ./...", []config.Exception{entry}, "Makefile excuses nothing", ""},
		{"workflow entry cannot excuse Makefile", "go test -timeout 45m ./internal/adopt/", []config.Exception{timeoutEntry("ci.yml", "2026-10-18")}, "Makefile:2 sets 45m", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("test:\n\t"+tc.command+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := auditTimeouts(t, root, tc.entries...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("AuditTestTimeouts = %q, %v; want %q", out, err, tc.wantErr)
				}
				return
			}
			if err != nil || !strings.Contains(out, tc.wantOut) {
				t.Fatalf("AuditTestTimeouts = %q, %v; want %q", out, err, tc.wantOut)
			}
		})
	}
}

// TestAuditTestTimeouts_MakefileDanglingContinuation refuses a Makefile whose last line ends in a
// continuation, naming that line.
func TestAuditTestTimeouts_MakefileDanglingContinuation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("test:\n\t$(GO_TEST) -race \\"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := auditTimeouts(t, root)
	if err == nil || !strings.Contains(err.Error(), "Makefile:2") {
		t.Fatalf("dangling continuation: %v; want Makefile:2 refused", err)
	}
}

// TestAuditTestTimeouts_ScanBound accepts a Makefile of exactly the line bound and refuses a Makefile
// or a workflow one line over it, so no line goes unaudited.
func TestAuditTestTimeouts_ScanBound(t *testing.T) {
	body := func(lines int) string { return "test:\n" + strings.Repeat("\t@true\n", lines-1) }
	atBound := t.TempDir()
	if err := os.WriteFile(filepath.Join(atBound, "Makefile"), []byte(body(maxTimeoutWorkflowLines)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := auditTimeouts(t, atBound); err != nil {
		t.Fatalf("Makefile at the %d-line bound: %q, %v; want a pass", maxTimeoutWorkflowLines, out, err)
	}
	over := t.TempDir()
	if err := os.WriteFile(filepath.Join(over, "Makefile"), []byte(body(maxTimeoutWorkflowLines+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("above the %d-line scan bound", maxTimeoutWorkflowLines)
	if _, err := auditTimeouts(t, over); err == nil || !strings.Contains(err.Error(), "Makefile has") || !strings.Contains(err.Error(), want) {
		t.Fatalf("Makefile over the bound: %v; want it refused naming the bound", err)
	}
	workflow := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test ./...\n" +
		strings.Repeat("#\n", maxTimeoutWorkflowLines)
	if _, err := auditTimeouts(t, triggerRepository(t, map[string]string{"long.yml": workflow})); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("workflow over the bound: %v; want it refused naming the bound", err)
	}
}

// Positive: a full-line Makefile comment that mentions go test and -timeout is not judged;
// a real recipe line in the same file is still scanned so a no-op pass cannot hide a dead scanner.
func TestAuditTestTimeouts_Positive_MakefileCommentIgnored(t *testing.T) {
	root := t.TempDir()
	body := "test:\n\t$(GO_TEST) -race -timeout 30m ./...\n" +
		"# -timeout replaces go test's ten-minute default per package\n" +
		"\tgo test -timeout 45m ./control/\n"
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := auditTimeouts(t, root)
	if err == nil || !strings.Contains(err.Error(), "Makefile:4 sets 45m") {
		t.Fatalf("Makefile comment: err = %v; want only the control recipe at line 4 refused", err)
	}
	if strings.Contains(err.Error(), "Makefile:3") || strings.Contains(err.Error(), "99m") {
		t.Fatalf("Makefile comment: err = %v; want no finding on the comment line", err)
	}
}

// Positive: an indented comment-only line in a workflow is not judged; a bound step in the same
// file is still scanned so a no-op pass cannot hide a dead scanner.
func TestAuditTestTimeouts_Positive_IndentedCommentIgnored(t *testing.T) {
	wf := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      # go test -timeout 99m ./...\n      - run: go test -timeout 30m ./...\n" +
		"      - run: go test -timeout 45m ./control/\n"
	_, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err == nil || !strings.Contains(err.Error(), ".github/workflows/ci.yml:8 sets 45m") {
		t.Fatalf("indented comment: err = %v; want only the control step at line 8 refused", err)
	}
	if strings.Contains(err.Error(), "ci.yml:6") || strings.Contains(err.Error(), "99m") {
		t.Fatalf("indented comment: err = %v; want no finding on the comment line", err)
	}
}

// Negative: a real go test line with a trailing comment is still judged.
func TestAuditTestTimeouts_Negative_TrailingCommentStillJudged(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("test:\n\tgo test -race -timeout 45m ./x # comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := auditTimeouts(t, root)
	if err == nil || !strings.Contains(err.Error(), "Makefile:2 sets 45m") {
		t.Fatalf("trailing comment: err = %v; want 45m flagged", err)
	}
}

// Negative: a recipe comment ending in a backslash ends at its own newline in the shell and cannot
// hide a long timeout on the following recipe lines.
func TestAuditTestTimeouts_Negative_ContinuedCommentDoesNotHideCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"recipe comment before go test", "test:\n\t# note \\\n\tgo test -race -timeout 45m ./x\n", "Makefile:3 sets 45m"},
		{"recipe comment before continued go test", "test:\n\t# note \\\n\t$(GO_TEST) -v -race \\\n\t  -timeout 45m ./internal/adopt/\n", "Makefile:3 sets 45m"},
		{"continued command then comment then go test", "test:\n\t@true; \\\n\t# note \\\n\tgo test -race -timeout 45m ./x\n", "Makefile:4 sets 45m"},
		{"dangling comment continuation", "test:\n\t# note \\", "Makefile:2 has an unfinished continuation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := auditTimeouts(t, root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want %q", err, tc.want)
			}
		})
	}
}

// Positive: a recipe comment ending in a backslash followed by a command within the bound passes,
// and a comment in a continued command does not inject a timeout token into that command.
func TestAuditTestTimeouts_Positive_ContinuedCommentWithinBound(t *testing.T) {
	root := t.TempDir()
	body := "test:\n\t# note \\\n\tgo test -race -timeout 30m ./x\n\t$(GO_TEST) -race -timeout 30m ./a; \\\n\t# -timeout 99m\n"
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := auditTimeouts(t, root)
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("continued comment within bound: %q, %v; want [PASS]", out, err)
	}
}

func TestAuditTestTimeouts_CommentLineSkipped(t *testing.T) {
	assertMakefileTimeout(t, "test:\n\t# go test -timeout 99m ./pkg/\n", "")
}

func TestAuditTestTimeouts_ContinuedRecipeComment(t *testing.T) {
	body := "test:\n\t# note \\\n\tgo test -race -timeout 45m ./x\n"
	assertMakefileTimeout(t, body, "Makefile:3 sets 45m")
}

// makefileCommentSemanticsCases covers top-level GNU make comment continuation, recipe comments
// with open shell quotes, and shell-comment EOL flush (PR 2034 CR11).
var makefileCommentSemanticsCases = []struct {
	name     string
	body     string
	wantErr  string
	wantPass bool
}{
	{
		name: "top-level continued comment hides go test",
		body: "# Disabled command: \\\n" +
			"go test -timeout 45m ./pkg/\n" +
			"test:\n\t@true\n",
		wantPass: true,
	},
	{
		name: "C13-06 bare top-level command after continued comment",
		body: "# note \\\n# also \\\n# end\n" +
			"go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name: "top-level comment without continuation then go test",
		body: "# disabled\n" +
			"go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "quoted hash in continued recipe",
		body:    "test:\n\tNOTE=\"a \\\n\t# b\" go test \\\n\t-timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "single-quoted hash continuation",
		body:    "test:\n\tNOTE='a \\\n\t# b' go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "quote closed before hash comment line",
		body:    "test:\n\tNOTE=\"a\" \\\n\t# note\n\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:4 sets 45m",
	},
	{
		name: "double-quoted hash line then shell comment ends command",
		body: "test:\n\tNOTE=\"a \\\n\t# b\" go test #c\\\n" +
			"\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:4 sets 45m",
	},
	{
		name: "single-quoted hash line then shell comment ends command",
		body: "test:\n\techo 'x \\\n\t#y' #c\\\n" +
			"\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:4 sets 45m",
	},
}

// TestAuditTestTimeouts_MakefileCommentSemantics covers top-level GNU make comment continuation,
// and recipe comments with open shell quotes.
func TestAuditTestTimeouts_MakefileCommentSemantics(t *testing.T) {
	for _, tc := range makefileCommentSemanticsCases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := auditTimeouts(t, root)
			if tc.wantPass {
				if err != nil || !strings.Contains(out, "[PASS]") {
					t.Fatalf("AuditTestTimeouts = %q, %v; want pass", out, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAuditTestTimeouts_RecipeCommentEndsAtNewline(t *testing.T) {
	body := "test:\n\techo a #c\\\n\tgo test -timeout 45m ./pkg/\n"
	assertMakefileTimeout(t, body, "Makefile:3 sets 45m")
}

func TestAuditTestTimeouts_TopLevelCommentContinues(t *testing.T) {
	body := "# Disabled command: \\\n" +
		"go test -timeout 45m ./pkg/\n" +
		"test:\n\t@true\n"
	assertMakefileTimeout(t, body, "")
}

// makefileGNUContinuationCases covers GNU make odd/even backslash continuation for recipes and
// top-level comments (PR 2034 rounds 3 and 4).
var makefileGNUContinuationCases = []struct {
	name     string
	body     string
	wantErr  string
	wantPass bool
}{
	{
		name:    "recipe continuation line starting with hash",
		body:    "test:\n\techo a\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe continued word through hash payload lines",
		body:    "test:\n\techo a\\\n\t#x\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe continuation line without tab starting with hash",
		body:    "test:\n\t@echo a\\\n#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:     "recipe comment after space before continuation backslash without tab",
		body:     "test:\n\techo a \\\n#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "top-level tab-indented continued comment before rule",
		body:     "\t# comment \\\n\tgo test -timeout 45m ./pkg/\ntest:\n\t@true\n",
		wantPass: true,
	},
	{
		name:     "recipe shell comment on continued hash line ends command",
		body:     "test:\n\techo a\\\n\t#x #c\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "recipe hash comment before continuation backslash",
		body:     "test:\n\techo #\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "recipe hash inside word before continuation backslash",
		body:    "test:\n\techo a#\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe quoted hash before continuation backslash",
		body:    "test:\n\techo '#'\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe escaped blank before hash before continuation backslash",
		body:    "test:\n\techo a\\ #\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe escaped backslash before hash before continuation backslash",
		body:    "test:\n\techo x \\\\#\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:     "recipe comment after space before continuation backslash",
		body:     "test:\n\techo a \\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "recipe space after tab before hash comment line",
		body:     "test:\n\techo a\\\n\t # go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "recipe semicolon before continuation backslash",
		body:     "test:\n\techo a;\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "recipe close-paren before continuation backslash",
		body:     "test:\n\techo a)\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:     "recipe pipe before continuation backslash",
		body:     "test:\n\techo a|\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "recipe escaped semicolon before continuation backslash",
		body:    "test:\n\techo a\\;\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:    "recipe make-variable ref before continuation backslash",
		body:    "NOTE := a\n" + "test:\n\techo $(NOTE)\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:3 sets 45m",
	},
	{
		name:    "recipe dollar-paren command sub before continuation backslash",
		body:    "test:\n\techo $$(cmd)\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:     "recipe subshell open-paren before continuation backslash",
		body:     "test:\n\t(echo a)\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "recipe escaped space before continuation backslash",
		body:    "test:\n\techo a\\ \\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:     "recipe escaped backslash then semicolon before continuation backslash",
		body:     "test:\n\techo a\\\\;\\\n\t#b; go test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "top-level comment even backslash pair before recipe",
		body:    "test:\n# note \\\\\n\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:3 sets 45m",
	},
	{
		name: "top-level comment single backslash hides next line",
		body: "# disabled \\\n" +
			"go test -timeout 45m ./pkg/\n" +
			"test:\n\t@true\n",
		wantPass: true,
	},
	{
		name: "top-level three trailing backslashes continue comment",
		body: "# note \\\\\\\n" +
			"go test -timeout 45m ./pkg/\n" +
			"test:\n\t@true\n",
		wantPass: true,
	},
	{
		name:     "top-level two trailing backslashes end comment",
		body:     "# note \\\\\n\tgo test -timeout 45m ./pkg/\n",
		wantPass: true,
	},
	{
		name:    "recipe even backslash pair ends command",
		body:    "test:\n\techo a\\\\\n\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:3 sets 45m",
	},
	{
		name:    "recipe shell comment on same line before continuation backslash",
		body:    "test:\n\techo a #c\\\n\tgo test -timeout 45m ./pkg/\n",
		wantErr: "Makefile:3 sets 45m",
	},
	{
		name:    "recipe go test with trailing shell comment before continuation backslash",
		body:    "test:\n\tgo test -timeout 45m ./a/ #c\\\n\tgo test -timeout 30m ./b/\n",
		wantErr: "Makefile:2 sets 45m",
	},
	{
		name:     "recipe shell comment on same line hides following within-bound go test",
		body:     "test:\n\techo a #c\\\n\tgo test -timeout 30m ./pkg/\n",
		wantPass: true,
	},
}

func TestAuditTestTimeouts_MakefileGNUContinuation(t *testing.T) {
	for _, tc := range makefileGNUContinuationCases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := auditTimeouts(t, root)
			if tc.wantPass {
				if err != nil || !strings.Contains(out, "[PASS]") {
					t.Fatalf("AuditTestTimeouts = %q, %v; want pass", out, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAuditTestTimeouts_Boundary_WordSpliceKeepsRecipeShellText(t *testing.T) {
	body := "test:\n\techo a\\\n\t#b; go test -timeout 45m ./pkg/\n"
	assertMakefileTimeout(t, body, "Makefile:2 sets 45m")
}

func TestAuditTestTimeouts_RecipeQuoteAcrossContinuation(t *testing.T) {
	body := "test:\n\tNOTE=\"a \\\n\t# b\" go test \\\n\t-timeout 45m ./pkg/\n"
	assertMakefileTimeout(t, body, "Makefile:2 sets 45m")
}

var makefileShellReaderCases = []struct {
	name string
	body string
	want string
}{
	{
		name: "C13-01 hash attached to substitution assignment",
		body: "test:\n\tNOTE=$$(printf x)#tag go test \\\n\t-timeout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "C13-02 empty recipe payload preserves continued word",
		body: "test:\n\techo a\\\n\t\\\n\t#b; go test -timeout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "C13-03 split flag",
		body: "test:\n\tgo test -time\\\n\tout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "split flag at the bound",
		body: "test:\n\tgo test -time\\\n\tout 30m ./pkg/\n",
	},
	{
		name: "second tab stays and splits the word",
		body: "test:\n\tgo test -time\\\n\t\tout 45m ./pkg/\n",
	},
	{
		name: "C13-04 inline comment timeout",
		body: "test:\n\tgo test -timeout 30m ./pkg/ # -timeout 99m\\\n\ttrue\n",
	},
	{
		name: "C13-04 quoted command text",
		body: "test:\n\techo 'go test -timeout 99m ./pkg/'\n",
	},
	{
		name: "another command's timeout text",
		body: "test:\n\tgo test -timeout 30m ./pkg/; echo -timeout 99m\n",
	},
	{
		name: "make expands dollars before the shell runs substitution",
		body: "test:\n\techo \"$$(go test -timeout 45m ./pkg/)\"\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "two escaped dollars produce the shell process ID",
		body: "test:\n\techo \"$$$$(go test -timeout 99m ./pkg/)\"\n",
	},
	{
		name: "brace make reference stays an opaque word",
		body: "test:\n\t${GO_TEST} --timeout=45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "make reference does not become shell code",
		body: "test:\n\techo $(call example,go test -timeout 99m ./pkg/)\n",
	},
	{
		name: "shell substitution is not the make test wrapper",
		body: "test:\n\t$$(GO_TEST) -timeout 99m ./pkg/\n",
	},
	{
		name: "quoted value from source",
		body: "test:\n\tgo test -timeout \"45m\" ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "quoted value at the bound",
		body: "test:\n\tgo test -timeout='30m' ./pkg/\n",
	},
	{
		name: "quoted assigned value from source",
		body: "test:\n\tgo test --timeout='45m' ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "quoted flag with adjacent quoted value fragments",
		body: "test:\n\tgo test '-timeout' \"4\"'5m' ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "quoted timeout text is one argument",
		body: "test:\n\tgo test '-timeout 99m' ./pkg/\n",
	},
	{
		name: "quoted unreadable value keeps its blanks",
		body: "test:\n\tgo test -timeout=\"45 m\" ./pkg/\n",
		want: "Makefile:2 sets 45 m, an unreadable timeout",
	},
	{
		name: "make timeout reference keeps its original spelling",
		body: "test:\n\tgo test -timeout $(DURATION) ./pkg/\n",
		want: "Makefile:2 sets $(DURATION), an unreadable timeout",
	},
	{
		name: "continued make comment swallows a tabbed command",
		body: "test:\n# disabled \\\n\tgo test -timeout 99m ./pkg/\n\tgo test -timeout 45m ./control/\n",
		want: "Makefile:4 sets 45m",
	},
	{
		name: "recipe begins after an inline rule separator",
		body: "test: ; go test -timeout 45m ./pkg/\n",
		want: "Makefile:1 sets 45m",
	},
	{
		name: "recipe inline rule continuation with hash",
		body: "test: ; @echo a\\\n#b; go test -timeout 45m ./pkg/\n",
		want: "Makefile:1 sets 45m",
	},
	{
		name: "recipe continuation empty payload preserves word across tab",
		body: "test:\n\t@echo a\\\n\t\\\n\t#b; go test -timeout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "recipe substitution continuation preserves word across tab",
		body: "test:\n\t@echo $$(printf '%s' \\\n\ta)\\\n\t#b; go test -timeout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "recipe quoted paren substitution preserves word across tab",
		body: "test:\n\t@echo $$(printf '%s' ')')\\\n\t#b; go test -timeout 45m ./pkg/\n",
		want: "Makefile:2 sets 45m",
	},
	{
		name: "tab alone does not open a recipe",
		body: "\tgo test -timeout 99m ./pkg/\n",
	},
	{
		name: "defined make text does not open a recipe",
		body: "define SAMPLE\ntest:\n\tgo test -timeout 99m ./pkg/\nendef\n",
	},
}

func TestAuditTestTimeouts_MakefileShellReader(t *testing.T) {
	for _, tc := range makefileShellReaderCases {
		t.Run(tc.name, func(t *testing.T) {
			assertMakefileTimeout(t, tc.body, tc.want)
		})
	}
}

func assertMakefileTimeout(t *testing.T, body, want string) {
	t.Helper()
	got, err := makefileTimeouts(body)
	if err != nil {
		t.Fatal(err)
	}
	if want == "" && len(got) == 0 {
		return
	}
	if want != "" && len(got) == 1 && strings.Contains(got[0], want) {
		return
	}
	t.Fatalf("makefileTimeouts = %v; want %q", got, want)
}

const repositoryControlTimeoutRecipe = "\tgo test -timeout 45m ./control/\n"

// copyRepositoryMakefileWithControlTimeout copies the checked-in Makefile from repoRoot into dir,
// appends a control-timeout target whose recipe exceeds the bound, and returns that recipe's line number.
func copyRepositoryMakefileWithControlTimeout(t *testing.T, repoRoot, dir string) int {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	recipeLine := strings.Count(body, "\n") + 2
	body += "control-timeout:\n" + repositoryControlTimeoutRecipe
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return recipeLine
}

// The checked-in recipe and declaration must exercise the same audit as adopter files.
func TestAuditTestTimeouts_RepositoryMakefile(t *testing.T) {
	root := filepath.Join("..", "..")
	manifest, err := config.LoadManifest(filepath.Join(root, config.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	// Pin the declaration's entry day; expiry itself is exercised by the negative fixture.
	today := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	opts := TestTimeoutOptions{Root: root, Exceptions: manifest.Exceptions, Today: today}
	out, err := AuditTestTimeouts(t.Context(), opts)
	if err != nil || !strings.Contains(out, "[PASS] test-timeout") {
		t.Fatalf("repository timeout audit = %q, %v; want the checked-in Makefile within the bound", out, err)
	}
	fork := t.TempDir()
	recipeLine := copyRepositoryMakefileWithControlTimeout(t, root, fork)
	want := fmt.Sprintf("Makefile:%d sets 45m", recipeLine)
	_, err = AuditTestTimeouts(t.Context(), TestTimeoutOptions{Root: fork, Exceptions: manifest.Exceptions, Today: today})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("forked Makefile audit: err = %v; want only %q refused", err, want)
	}
	if strings.Count(err.Error(), "Makefile:") != 1 {
		t.Fatalf("forked Makefile audit: err = %v; want exactly one Makefile finding", err)
	}
}

// Negative: raw YAML physical line starting with # inside a quoted run scalar decodes to shell code.
func TestAuditTestTimeouts_Negative_YAMLQuotedRunContinuationWithHash(t *testing.T) {
	wf := "name: test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: \"echo a\\\n    #b; go test -timeout 45m ./pkg/\"\n"
	_, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err == nil || !strings.Contains(err.Error(), ".github/workflows/ci.yml:7 sets 45m") {
		t.Fatalf("yaml quoted run: err = %v; want .github/workflows/ci.yml:7 sets 45m", err)
	}
}

// Boundary: raw YAML physical line with hash inside a within-bound quoted run scalar passes.
func TestAuditTestTimeouts_Boundary_YAMLQuotedRunContinuationWithHashPasses(t *testing.T) {
	wf := "name: test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: \"echo a\\\n    #b; go test -timeout 30m ./pkg/\"\n"
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("yaml quoted run within bound: %q, %v; want [PASS]", out, err)
	}
}

// TestAuditTestTimeouts_WorkflowShellCommands checks shell syntax and document line mapping.
func TestAuditTestTimeouts_WorkflowShellCommands(t *testing.T) {
	const prefix = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, tc := range []struct {
		name, step, want string
	}{
		{"continued timeout", "      - run: |\n\n          go test \\\n            -timeout 45m ./pkg/\n", "ci.yml:8 sets 45m"},
		{"quoted command and arguments", "      - run: |\n          'g'\\\n          'o' test '-timeout' '45'\"m\" ./pkg/\n", "ci.yml:7 sets 45m"},
		{"trailing shell comment", "      - run: |\n          go test -timeout 30m ./pkg/ # -timeout 99m\n", ""},
		{"folded value", "      - run: >-\n          go test\n          -timeout 45m ./pkg/\n", "ci.yml:6 sets 45m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": prefix + tc.step}))
			if tc.want == "" && err == nil && strings.Contains(out, "[PASS]") {
				return
			}
			if tc.want != "" && err != nil && strings.Contains(err.Error(), tc.want) {
				return
			}
			t.Fatalf("AuditTestTimeouts = %q, %v; want %q", out, err, tc.want)
		})
	}
}

// TestAuditTestTimeouts_UnreadableWorkflow requires an explicit failure for both parser stages.
func TestAuditTestTimeouts_UnreadableWorkflow(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		entries          []config.Exception
	}{
		{name: "malformed YAML", body: boundWorkflow + "invalid: [\n", want: "parse workflow: yaml:"},
		{
			name:    "too many steps with live exception",
			body:    longWorkflow + strings.Repeat("      - run: echo hello\n", ghworkflow.MaxStepsPerJob),
			want:    fmt.Sprintf("workflow job test exceeds %d steps", ghworkflow.MaxStepsPerJob),
			entries: []config.Exception{timeoutEntry("ci.yml", "2026-10-18")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": tc.body}), tc.entries...)
			if err == nil || !strings.Contains(err.Error(), "[FAIL] test-timeout: .github/workflows/ci.yml") ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("AuditTestTimeouts = %q, %v; want a workflow failure with %q", out, err, tc.want)
			}
		})
	}
}

// TestAuditTestTimeouts_UnreadableWorkflowShell requires a finding for an unfinished shell word.
func TestAuditTestTimeouts_UnreadableWorkflowShell(t *testing.T) {
	wf := strings.Replace(boundWorkflow, "./...", `./... "`, 1)
	out, err := auditTimeouts(t, triggerRepository(t, map[string]string{"ci.yml": wf}))
	const want = "[FAIL] test-timeout: .github/workflows/ci.yml:7 has unreadable shell run script"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("AuditTestTimeouts = %q, %v; want %q", out, err, want)
	}
}
