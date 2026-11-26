// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/gomanifest"
	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/testsupport"
	"github.com/cordanaLLM/praetor/internal/util"
)

var timeoutsToday = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const literalWrapperDefinition = "GO_TEST := go test\n"

const boundWorkflow = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n" +
	"    steps:\n      - run: go test -timeout 30m ./...\n"

const longWorkflow = "on: push\njobs:\n  test:\n    runs-on: windows-latest\n" +
	"    steps:\n      - run: go test -timeout 60m ./internal/adopt\n        shell: bash\n"

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
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("test:\n\t"+tc.command+"\n"+literalWrapperDefinition), 0o600); err != nil {
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
		"\tgo test -timeout 45m ./control/\n" + literalWrapperDefinition
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
		{"recipe comment before continued go test", "test:\n\t# note \\\n\t$(GO_TEST) -v -race \\\n\t  -timeout 45m ./internal/adopt/\n" + literalWrapperDefinition, "Makefile:3 sets 45m"},
		{"continued command then comment then go test", "test:\n\t@true; \\\n\t# note \\\n\tgo test -race -timeout 45m ./x\n", "Makefile:4 sets 45m"},
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
	body := "test:\n\t# note \\\n\tgo test -race -timeout 30m ./x\n\t$(GO_TEST) -race -timeout 30m ./a ; \\\n\t# -timeout 99m\n" + literalWrapperDefinition
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := auditTimeouts(t, root)
	if err != nil || !strings.Contains(out, "[PASS]") {
		t.Fatalf("continued comment within bound: %q, %v; want [PASS]", out, err)
	}
}

// TestAuditTestTimeouts_CommentLineSkipped pins the behavior that commented recipe lines are ignored during timeout auditing.
func TestAuditTestTimeouts_CommentLineSkipped(t *testing.T) {
	assertMakefileTimeout(t, "test:\n\t# go test -timeout 99m ./pkg/\n", "")
}

// TestAuditTestTimeouts_ContinuedRecipeComment pins detection of timeouts when a recipe comment ends in a backslash continuation.
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

// TestAuditTestTimeouts_RecipeCommentEndsAtNewline pins termination of inline recipe comments at newlines despite trailing backslashes.
func TestAuditTestTimeouts_RecipeCommentEndsAtNewline(t *testing.T) {
	body := "test:\n\techo a #c\\\n\tgo test -timeout 45m ./pkg/\n"
	assertMakefileTimeout(t, body, "Makefile:3 sets 45m")
}

// TestAuditTestTimeouts_TopLevelCommentContinues pins continuation of top-level Makefile comments across backslash line breaks.
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

// TestAuditTestTimeouts_Boundary_WordSpliceKeepsRecipeShellText pins detection of timeouts in recipe shell commands spliced across continuations.
func TestAuditTestTimeouts_Boundary_WordSpliceKeepsRecipeShellText(t *testing.T) {
	body := "test:\n\techo a\\\n\t#b; go test -timeout 45m ./pkg/\n"
	assertMakefileTimeout(t, body, "Makefile:2 sets 45m")
}

// TestAuditTestTimeouts_RecipeQuoteAcrossContinuation pins detection of timeouts when quotes span line continuations in recipe commands.
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
		want: "Makefile:2 unverifiable test invocation: unexpanded argument",
	},
	{
		name: "C13-04 inline comment timeout",
		body: "test:\n\tgo test -timeout 30m ./pkg/ # -timeout 99m\\\n\ttrue\n",
	},
	{
		name: "unindented comment after continued package list",
		body: "test:\n\tgo test ./... \\\n# -timeout 45m\n",
	},
	{
		name: "C13-04 quoted command text",
		body: "test:\n\techo 'go test -timeout 99m ./pkg/'\n",
		want: "Makefile:2 unverifiable test invocation: raw test tokens do not resolve to a literal command",
	},
	{
		name: "another command's timeout text",
		body: "test:\n\tgo test -timeout 30m ./pkg/ ; echo -timeout 99m\n",
	},
	{
		name: "make expands dollars before the shell runs substitution",
		body: "test:\n\techo \"$$(go test -timeout 45m ./pkg/)\"\n",
		want: "Makefile:2 unverifiable test invocation: operator attached",
	},
	{
		name: "two escaped dollars produce the shell process ID",
		body: "test:\n\techo \"$$$$(go test -timeout 99m ./pkg/)\"\n",
		want: "Makefile:2 unverifiable test invocation: raw test tokens do not resolve to a literal command",
	},
	{
		name: "brace make reference stays an opaque word",
		body: "test:\n\t${GO_TEST} --timeout=45m ./pkg/\n" + literalWrapperDefinition,
		want: "Makefile:2 sets 45m",
	},
	{
		name: "make reference does not become shell code",
		body: "test:\n\techo $(call example,go test -timeout 99m ./pkg/)\n",
		want: "Makefile:2 unverifiable test invocation: unexpanded Make construct in recipe",
	},
	{
		name: "shell substitution is not the make test wrapper",
		body: "test:\n\t$$(GO_TEST) -timeout 99m ./pkg/\n",
		want: "Makefile:2 unverifiable test invocation: raw test tokens do not resolve to a literal command",
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
		want: "Makefile:2 unverifiable test invocation: unexpanded argument",
	},
	{
		name: "quoted unreadable value keeps its blanks",
		body: "test:\n\tgo test -timeout=\"45 m\" ./pkg/\n",
		want: "Makefile:2 unverifiable test invocation: 45 m is an unreadable timeout",
	},
	{
		name: "make timeout reference keeps its original spelling",
		body: "test:\n\tgo test -timeout $(DURATION) ./pkg/\n",
		want: "Makefile:2 unverifiable test invocation: $(DURATION) is an unreadable timeout",
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

// TestAuditTestTimeouts_MakefileShellReader runs table cases verifying timeout extraction from varied Makefile structures.
func TestAuditTestTimeouts_MakefileShellReader(t *testing.T) {
	for _, tc := range makefileShellReaderCases {
		t.Run(tc.name, func(t *testing.T) {
			assertMakefileTimeout(t, tc.body, tc.want)
		})
	}
}

// assertMakefileTimeout parses a Makefile body and asserts that detected timeout diagnostics match the expected string.
func assertMakefileTimeout(t *testing.T, body, want string) {
	t.Helper()
	got, err := makefileTimeouts(body)
	if err != nil {
		got = append(got, strings.Split(err.Error(), "\n")...)
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
	t.Run("shared invocation selects adopt", func(t *testing.T) {
		checkRepositoryTestPackages(t, root)
	})
}

// checkRepositoryTestPackages expands both checked-in test recipes over two real Go packages.
func checkRepositoryTestPackages(t *testing.T, repoRoot string) {
	t.Helper()
	makePath := testsupport.GNUMake(t)
	body, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"MAKEFILES", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS"} {
		t.Setenv(key, "")
	}
	env := util.FilterEnvironment(testsupport.OfflineGoEnv(t), func(key string) bool { return strings.HasPrefix(key, "GIT_") })
	ctx, err := util.WithCommandEnvironment(t.Context(), env)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeForgeTestFile(t, root, "go.mod", "module "+gomanifest.EngineModulePath+"\n")
	writeForgeTestFile(t, root, "internal/adopt/adopt.go", "package adopt\n")
	writeForgeTestFile(t, root, "internal/control/control.go", "package control\n")
	for _, tc := range []struct {
		name, extra string
		wantAdopt   bool
	}{
		{"checked in", "", true},
		{"adopt excluded", "\nTEST_PACKAGES := $(filter-out %/internal/adopt,$(TEST_PACKAGES))\n", false},
	} {
		writeForgeTestFile(t, root, "Makefile", string(body)+tc.extra)
		for _, profile := range []string{"", "coverage.out"} {
			out, err := util.RunCommand(ctx, root, makePath, "-n", "--no-print-directory", "test",
				"GO_TEST=go test", "HOOK_GO_SOURCES=", "TEST_COVERPROFILE="+profile)
			if err != nil {
				t.Fatalf("%s, profile %q: %v", tc.name, profile, err)
			}
			if got := sharedTestSelectsAdopt(t, out); got != tc.wantAdopt {
				t.Fatalf("%s, profile %q: shared invocation selects adopt = %v, want %v:\n%s", tc.name, profile, got, tc.wantAdopt, out)
			}
		}
	}
}

// sharedTestSelectsAdopt checks membership on the 30m Go test command that also selects the control package.
func sharedTestSelectsAdopt(t *testing.T, recipe string) bool {
	t.Helper()
	commands, ok := hiss.ShellCodeCommands(recipe, maxTimeoutWorkflowLines, nil)
	if !ok {
		t.Fatalf("unreadable expanded test recipe:\n%s", recipe)
	}
	for _, command := range commands {
		args := goTestArgs(command.Words)
		var values []string
		var timeout string
		for i := 0; i < len(args); i++ {
			if value, next, found := timeoutValue(args, i); found {
				timeout = value
				i = next
			} else {
				values = append(values, args[i].Value)
			}
		}
		if timeout == "30m" && slices.Contains(values, gomanifest.EngineModulePath+"/internal/control") {
			return slices.Contains(values, gomanifest.EngineModulePath+"/internal/adopt")
		}
	}
	t.Fatalf("missing shared 30m go test for the control package:\n%s", recipe)
	return false
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
		{"quoted command and arguments", "      - run: |\n          'g'\\\n          'o' test '-timeout' '45'\"m\" ./pkg/\n", "ci.yml:7 unverifiable test invocation"},
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
	const want = "[FAIL] test-timeout: .github/workflows/ci.yml:7 unverifiable test invocation: unreadable shell run script"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("AuditTestTimeouts = %q, %v; want %q", out, err, want)
	}
}

// timeoutFixtureWorkflow gives a single step a concrete runner for interpreter resolution.
func timeoutFixtureWorkflow(runner, step string) string {
	return "on: push\njobs:\n  test:\n    runs-on: " + runner + "\n    steps:\n" + step
}

// assertTimeoutFile exercises the public audit and requires exactly the expected finding or pass.
func assertTimeoutFile(t *testing.T, file, body, want string) {
	t.Helper()
	root := t.TempDir()
	writeForgeTestFile(t, root, file, body)
	out, err := auditTimeouts(t, root)
	if want == "" {
		if err != nil || out != "[PASS] test-timeout" {
			t.Fatalf("AuditTestTimeouts = %q, %v; want a pass", out, err)
		}
		return
	}
	if err == nil || err.Error() != "[FAIL] test-timeout: "+file+want {
		t.Fatalf("AuditTestTimeouts = %q, %v; want one finding at %s%s", out, err, file, want)
	}
}

// TestAuditTestTimeouts_UnverifiableInvocations plants each unsupported shape in a repository file.
func TestAuditTestTimeouts_UnverifiableInvocations(t *testing.T) {
	const workflow = ".github/workflows/ci.yml"
	const refused = " unverifiable test invocation: "
	const flag = "unsupported Go global flag or operand (expected -C dir)"
	const operation = "operator attached to an invocation word"
	for _, tc := range []struct{ name, file, body, want string }{
		{"windows assignment", workflow, timeoutFixtureWorkflow("windows-latest", "      - run: $result = go test -timeout 45m ./...\n"),
			":6" + refused + `resolved shell "pwsh" must be bash or sh`},
		{"unresolved runner", workflow, timeoutFixtureWorkflow("self-hosted", "      - run: go test -timeout 30m\n"),
			":6" + refused + `resolved shell "" must be bash or sh`},
		{"Make shell", "Makefile", "test:\n\t@echo $(shell go test -timeout 45m ./pkg)\n", ":2" + refused + "unexpanded Make construct in recipe"},
		{"short equals flag", "Makefile", "test:\n\tgo -C=. test -timeout 45m ./...\n", ":2" + refused + flag},
		{"long equals flag", "Makefile", "test:\n\tgo.exe --C=. test -timeout 45m ./...\n", ":2" + refused + flag},
		{"long separate flag", "Makefile", "test:\n\tgo --C . test -timeout 45m ./...\n", ":2" + refused + flag},
		{"redirection", workflow, timeoutFixtureWorkflow("ubuntu-latest", "      - run: go test>test.log -timeout 45m ./...\n"), ":6" + refused + operation},
		{"joined pipe", "Makefile", "test:\n\tgo test -timeout 30m ./pkg|cat\n", ":2" + refused + operation},
		{"one shell", "Makefile", "test:\n\tgo test -timeout 30m ./...\n.ONESHELL:\n", ":2" + refused + ".ONESHELL recipes share a shell"},
		{"inline separator past bound", "Makefile", "test:" + strings.Repeat(" ", util.MaxMakefileLineBytes) + "; go test -timeout 45m ./...\n",
			":1" + refused + fmt.Sprintf("logical line exceeds the %d-byte reader bound", util.MaxMakefileLineBytes)},
		{"hidden second candidate", "Makefile", "test:\n\tgo test -timeout 30m ; custom go test -timeout 45m\n", ":2" + refused + "raw test tokens do not resolve to a literal command"},
		{"computed flag", "Makefile", "test:\n\tgo test -time$(SUFFIX) 45m\n", ":2" + refused + "unexpanded argument in test invocation"},
		{"computed -C operand", workflow, timeoutFixtureWorkflow("ubuntu-latest", "      - run: go -C $(printf .) test -timeout 45m\n"), ":6" + refused + flag},
		{"excess flags", "Makefile", "test:\n\tgo test" + strings.Repeat(" -timeout 30m", maxTimeoutFlagsPerCommand) + " -timeout 45m\n",
			":2" + refused + "timeout flag count exceeds the reader bound"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertTimeoutFile(t, tc.file, tc.body, tc.want) })
	}
}

// TestAuditTestTimeouts_UnrelatedMultilineExpression checks both sides of the raw candidate filter.
func TestAuditTestTimeouts_UnrelatedMultilineExpression(t *testing.T) {
	const workflow = ".github/workflows/ci.yml"
	const step = "      - run: |\n          echo \"${{\n            github.ref }}\"\n"
	assertTimeoutFile(t, workflow, timeoutFixtureWorkflow("ubuntu-latest", step), "")
	assertTimeoutFile(t, workflow, timeoutFixtureWorkflow("ubuntu-latest", step+"          go test ./...\n"),
		":9 unverifiable test invocation: unreadable shell run script or shell reader bound")
	assertTimeoutFile(t, "Makefile", ".ONESHELL:\ntest:\n\tcat <<'END'\n\thello\n\tEND\n", "")
	assertTimeoutFile(t, "Makefile", "test:\n\t# note \\", "")
	assertTimeoutFile(t, "Makefile", "test:\n\techo \"unclosed\n\tgo test -timeout 30m\n", "")
	assertTimeoutFile(t, workflow, timeoutFixtureWorkflow("self-hosted", "      - run: echo my-go test go test-data\n"), "")
}

// TestAuditTestTimeouts_LiteralInvocations checks the same boundary on workflows and recipes.
func TestAuditTestTimeouts_LiteralInvocations(t *testing.T) {
	for _, duration := range []string{"30m", "45m"} {
		command := "go -C . test -timeout " + duration + " ./...\n"
		recipeWant, workflowWant := "", ""
		if duration == "45m" {
			recipeWant = ":2 sets 45m, above the 30m bound"
			workflowWant = ":7 sets 45m, above the 30m bound"
		}
		assertTimeoutFile(t, "Makefile", "test:\n\t"+command, recipeWant)
		step := "      - shell: sh\n        run: " + command
		assertTimeoutFile(t, ".github/workflows/ci.yml", timeoutFixtureWorkflow("windows-latest", step), workflowWant)
	}
}

// TestAuditTestTimeouts_InheritedShell checks workflow and job defaults and the step override.
func TestAuditTestTimeouts_InheritedShell(t *testing.T) {
	const file = ".github/workflows/ci.yml"
	wf := "defaults: {run: {shell: sh}}\n" + timeoutFixtureWorkflow("windows-latest", "      - run: go.exe test -timeout 30m\n")
	assertTimeoutFile(t, file, wf, "")
	wf = strings.Replace(wf, "    steps:", "    defaults: {run: {shell: cmd}}\n    steps:", 1)
	assertTimeoutFile(t, file, wf, `:8 unverifiable test invocation: resolved shell "cmd" must be bash or sh`)
	assertTimeoutFile(t, file, wf+"        shell: bash\n", "")
}

// TestAuditTestTimeouts_TestFlagSpellings checks Go's timeout aliases at and above the bound.
func TestAuditTestTimeouts_TestFlagSpellings(t *testing.T) {
	for _, flag := range []string{"-timeout", "--timeout", "-test.timeout", "--test.timeout"} {
		for _, sep := range []string{" ", "="} {
			for _, tc := range []struct{ duration, want string }{
				{"30m", ""},
				{"45m", ":2 sets 45m, above the 30m bound"},
			} {
				t.Run(flag+sep+tc.duration, func(t *testing.T) {
					cmd := "go test " + flag + sep + tc.duration + " ./..."
					assertTimeoutFile(t, "Makefile", "test:\n\t"+cmd+"\n", tc.want)
				})
			}
		}
	}
}

// TestAuditTestTimeouts_ArgumentRoles distinguishes scalar flag values and proven package operands.
func TestAuditTestTimeouts_ArgumentRoles(t *testing.T) {
	const file = ".github/workflows/ci.yml"
	const refused = ":7 unverifiable test invocation: unexpanded argument in test invocation"
	for _, tc := range []struct{ name, command, want string }{
		{"computed first flag", `flag=-timeout=45m; go test "$flag" ./...`, refused},
		{"computed global flag", `go "$flag" test ./...`, ":7 unverifiable test invocation: raw test tokens do not resolve to a literal command"},
		{"computed last flag", `flag=-test.timeout=45m; go test ./... "$flag"`, refused},
		{"unbound package", `go test -timeout 30m "$pkg"`, refused},
		{"literal package binding", `pkg=./internal/adopt && go test -timeout 30m "$pkg"`, ""},
		{"quoted package path", `go test "./$pkg"`, ""},
		{"quoted package array", `go test "${packages[@]##-*}"`, ""},
		{"quoted value", `go test -run "$filter" ./...`, ""},
		{"empty quoted value", `go test -run '' ./...`, ""},
		{"value consumes flag spelling", `go test -run -timeout=45m ./...`, ""},
		{"array in value slot", `go test -run "${args[@]}" ./...`, refused},
		{"unknown literal flag", "go test -unknown ./...", refused},
		{"missing value", "go test -run", refused},
		{"resumed package list", "go test ./pkg -run Test ./other", ":7 unverifiable test invocation: package operand after the package list ended"},
		{"words after terminator", "go test -- -test.timeout=45m", refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := "      - run: |\n          " + tc.command + "\n"
			assertTimeoutFile(t, file, timeoutFixtureWorkflow("ubuntu-latest", step), tc.want)
		})
	}
}

// TestAuditTestTimeouts_MakeArgumentRoles checks Make expansions before shell quote removal.
func TestAuditTestTimeouts_MakeArgumentRoles(t *testing.T) {
	const refused = ":2 unverifiable test invocation: unexpanded argument in test invocation"
	for _, tc := range []struct{ definition, args, want string }{
		{"FLAGS := -timeout=45m", "$(FLAGS)", refused},
		{"FLAGS := x -timeout=45m", "-run $(FLAGS)", refused},
		{"FLAGS := x -timeout=45m", "./... > $(FLAGS)", ":2 unverifiable test invocation: unsupported redirection or operator attached to an invocation word"},
		{"PKG := ./internal/adopt", "$(PKG)", ""},
		{"FILTER := TestAdopt", "-run ${FILTER} ./...", ""},
		{"", `-run "$$filter" ./...`, ""},
		{"", `-run "$filter" ./...`, ":2 unverifiable test invocation: unexpanded Make construct in recipe"},
	} {
		body := tc.definition + "\ntest: ; go test " + tc.args + "\n"
		assertTimeoutFile(t, "Makefile", body, tc.want)
	}
}

// TestAuditTestTimeouts_WrapperDefinition checks both halves of the effective argument list.
func TestAuditTestTimeouts_WrapperDefinition(t *testing.T) {
	const long = ":2 sets 45m, above the 30m bound"
	const refused = ":2 unverifiable test invocation: GO_TEST needs one literal test command in a root Makefile assignment"
	for _, tc := range []struct{ definition, use, want string }{
		{"GO_TEST := go test -timeout=45m", "$(GO_TEST) ./...", long},
		{"GO_TEST := go test -timeout=30m", "${GO_TEST} ./...", ""},
		{"GO_TEST := go test -timeout", "$(GO_TEST) 45m ./...", long},
		{"GO_TEST := go test -timeout=30m", "${GO_TEST} --test.timeout 45m ./...", long},
		{"GO_TEST ?= go test", "$(GO_TEST) ./...", refused},
		{"GO_TEST := $(COMMAND)", "${GO_TEST} ./...", refused},
		{"GO_TEST := go test ; echo", "$(GO_TEST) ./...", refused},
		{"test: GO_TEST := go test", "$(GO_TEST) ./...", refused},
		{"", "${GO_TEST} -timeout 30m", refused},
	} {
		body := tc.definition + "\ntest: ; " + tc.use + "\n"
		assertTimeoutFile(t, "Makefile", body, tc.want)
	}
	body := "GO_TEST := go test\ntest: ; $(GO_TEST) ./...\n"
	assertTimeoutFile(t, "Makefile", body+"GO_TEST += -timeout=45m\n", refused)
	assertTimeoutFile(t, "Makefile", body+"include flags.mk\n", refused)
	assertTimeoutFile(t, "Makefile", body+"extra:\n\t$(eval GO_TEST += -timeout=45m)\n", refused)
	const conditional = "ifdef EXTRA\nGO_TEST := go test\nendif\ntest: ; $(GO_TEST) ./...\n"
	assertTimeoutFile(t, "Makefile", conditional, strings.Replace(refused, ":2", ":4", 1))
}

// TestAuditTestTimeouts_ProgramSpelling keeps every transformed executable visible to the candidate filter.
func TestAuditTestTimeouts_ProgramSpelling(t *testing.T) {
	const file = ".github/workflows/ci.yml"
	const refused = ":8 unverifiable test invocation: raw test tokens do not resolve to a literal command"
	for _, name := range []string{"go.e'xe'", `go."ex"e`, `go.ex\e`, "go.e\\\n          xe", "'go'", "/bin/go"} {
		step := "      - shell: bash\n        run: |\n          " + name + " test -timeout 45m ./...\n"
		assertTimeoutFile(t, file, timeoutFixtureWorkflow("windows-latest", step), refused)
	}
	step := "      - shell: bash\n        run: go.exe test -test.timeout=30m ./...\n"
	assertTimeoutFile(t, file, timeoutFixtureWorkflow("windows-latest", step), "")
}

// TestAuditTestTimeouts_CheckedInEntryPoints audits each repository test source without exceptions.
func TestAuditTestTimeouts_CheckedInEntryPoints(t *testing.T) {
	for _, file := range []string{"Makefile", ".github/workflows/portability.yml"} {
		t.Run(file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
			if err != nil {
				t.Fatal(err)
			}
			assertTimeoutFile(t, file, string(body), "")
		})
	}
}
