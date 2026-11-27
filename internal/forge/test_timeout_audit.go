// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

// testTimeoutGate names the check in its lines.
const testTimeoutGate = "test-timeout"

// testTimeoutBoundMinutes is the go test timeout workflows and Makefile keep per package (#1381).
const testTimeoutBoundMinutes = 30

// inputExpression matches a value that is exactly ${{ inputs.<id> }}.
var inputExpression = regexp.MustCompile(`^\$\{\{\s*inputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$`)

const (
	maxTimeoutWorkflowLines   = 20000
	maxTimeoutFlagsPerCommand = 16
)

// TestTimeoutOptions is what AuditTestTimeouts reads: the repository root, the manifest's
// exceptions list (the check reads the entries of config.ExceptionRuleTestTimeout) and the day
// those entries' expiry is judged against.
type TestTimeoutOptions struct {
	Root       string
	Exceptions []config.Exception
	Today      time.Time
}

// AuditTestTimeouts checks workflow and root Makefile lines against the per-package timeout
// bound. It proves commands in bash or sh workflow steps (step, job, workflow, then runner
// default) and literal Makefile recipes without .ONESHELL, including named test-command assignments.
// Before test, go or go.exe may take only the two-word -C dir. Each raw candidate must map to
// a resolved command or shell comment. Unknown shells, enclosing Make functions, attached
// operators and incomplete reads report an unverifiable test invocation at its source line.
func AuditTestTimeouts(ctx context.Context, opts TestTimeoutOptions) (string, error) {
	files, err := readTestTimeoutFiles(ctx, opts.Root)
	if err != nil {
		return "", err
	}
	entries := config.ExceptionsFor(opts.Exceptions, config.ExceptionRuleTestTimeout)
	used := make([]bool, len(entries))
	var findings, excepted []string
	unreadable := make(map[string]bool)
	for _, file := range files {
		rel := file.Name
		long, err := fileTimeouts(file)
		if err != nil {
			unreadable[rel] = true
			findings = append(findings, err.Error())
		}
		if len(long) == 0 {
			continue
		}
		live, expired := config.ExceptionFor(entries, rel, opts.Today, used)
		if live != nil {
			excepted = append(excepted, fmt.Sprintf("[PASS] %s: %s excepted until %s: %s", testTimeoutGate, rel, live.Expires, live.Reason))
			continue
		}
		if expired != nil {
			findings = append(findings, fmt.Sprintf("[FAIL] %s: the exceptions entry for %s expired %s; bring the timeout back to the bound or renew the entry with a reason", testTimeoutGate, rel, expired.Expires))
		}
		findings = append(findings, long...)
	}
	findings = append(findings, staleTimeoutEntries(entries, used, unreadable)...)
	if len(findings) > 0 {
		return "", errors.New(strings.Join(findings, "\n"))
	}
	return strings.Join(append(excepted, "[PASS] test-timeout"), "\n"), nil
}

// staleTimeoutEntries reports exceptions that no measured timeout needed in a fully read file.
func staleTimeoutEntries(entries []config.Exception, used []bool, unreadable map[string]bool) []string {
	var stale []string
	for i, entry := range entries {
		if !used[i] && !unreadable[entry.Target()] {
			stale = append(stale, fmt.Sprintf("[FAIL] %s: the exceptions entry for %s excuses nothing, because the file keeps the bound; remove it", testTimeoutGate, entry.Target()))
		}
	}
	return stale
}

// fileTimeouts returns the long go test timeouts in Makefile recipes or decoded workflow scripts.
func fileTimeouts(file workflowFile) ([]string, error) {
	if lines := physicalLines(string(file.Data)); lines > maxTimeoutWorkflowLines {
		return nil, unverifiableTestInvocation(file.Name, maxTimeoutWorkflowLines+1,
			fmt.Sprintf("%s has %d lines, above the %d-line scan bound", file.Name, lines, maxTimeoutWorkflowLines))
	}
	if file.Name == "Makefile" {
		return makefileTimeouts(string(file.Data))
	}
	return workflowTimeouts(file.Name, file.Data)
}

// physicalLines counts the lines of text; a final newline ends the last line instead of starting
// an empty one, so a file of exactly the bound with a trailing newline stays within it.
func physicalLines(text string) int {
	if text == "" {
		return 0
	}
	lines := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		lines++
	}
	return lines
}

// goTestArgs returns the arguments following a supported Go test command head.
func goTestArgs(words []hiss.ShellCodeWord) []hiss.ShellCodeWord {
	program := words[0]
	if program.Text != "go" && program.Text != "go.exe" || program.Span[1]-program.Span[0] != len(program.Text) {
		return nil
	}
	tail := skipGoDirectory(words[1:])
	if len(tail) > 0 && tail[0].Value == "test" {
		return tail[1:]
	}
	return nil
}

// skipGoDirectory consumes the optional global -C and its literal directory as a pair.
func skipGoDirectory(words []hiss.ShellCodeWord) []hiss.ShellCodeWord {
	if len(words) >= 2 && words[0].Value == "-C" && literalGoDirectory.MatchString(words[1].Value) {
		return words[2:]
	}
	return words
}

// readTestTimeoutFiles retains workflow paths and adds the optional root Makefile through the
// same bounded, symlink-resistant snapshot reader used for repository source files.
func readTestTimeoutFiles(ctx context.Context, root string) ([]workflowFile, error) {
	files, err := readWorkflowFiles(ctx, root)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(files) && i < maxWorkflowFiles; i++ {
		files[i].Name = ghworkflow.Dir + "/" + files[i].Name
	}
	data, err := contextopt.ReadSnapshot(ctx, filepath.Join(root, "Makefile"))
	if errors.Is(err, os.ErrNotExist) {
		return files, nil
	}
	if err != nil {
		return nil, fmt.Errorf("test-timeout Makefile: %w", err)
	}
	return append(files, workflowFile{Name: "Makefile", Data: data}), nil
}

// judgeTimeout returns the finding for one -timeout value at where, "" within the bound. A value
// ${{ inputs.<id> }} is judged by that input's workflow_call default; an input without a
// literal default the gate can read is unreadable, as any other value it cannot parse.
func parseTimeoutDuration(raw string, defaults map[string]exprValue) (d time.Duration, shown, reason string) {
	value, shown := raw, raw
	if input := inputExpression.FindStringSubmatch(raw); input != nil {
		def, ok := defaults[input[1]]
		if !ok {
			return 0, "", fmt.Sprintf("%s is an unreadable timeout: the input has no literal default", raw)
		}
		value, shown = def.text, fmt.Sprintf("%s (default %s)", raw, def.text)
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, "", fmt.Sprintf("%s is an unreadable timeout", shown)
	}
	return d, shown, ""
}

func judgeTimeout(where, raw string, defaults map[string]exprValue) (finding, reason string) {
	d, shown, reason := parseTimeoutDuration(raw, defaults)
	if reason != "" {
		return "", reason
	}
	if d <= 0 {
		return "", fmt.Sprintf("%s disables the test deadline", shown)
	}
	if d > time.Duration(testTimeoutBoundMinutes)*time.Minute {
		return fmt.Sprintf("[FAIL] %s: %s sets %s, above the %dm bound", testTimeoutGate, where, shown, testTimeoutBoundMinutes), ""
	}
	return "", ""
}

// workflowTimeoutReadError locates the candidate that an incomplete workflow read could not check.
func workflowTimeoutReadError(rel string, data []byte, err error) error {
	if at := rawTestCandidate(string(data)); at != nil {
		return unverifiableTestInvocation(rel, 1+bytes.Count(data[:at[0]], []byte("\n")), err.Error())
	}
	return fmt.Errorf("[FAIL] %s: %s: %w", testTimeoutGate, rel, err)
}

// workflowTimeouts audits decoded run steps and refuses workflows it cannot read.
func workflowTimeouts(rel string, data []byte) ([]string, error) {
	spec, err := ghworkflow.Parse(data)
	if err != nil {
		return nil, workflowTimeoutReadError(rel, data, err)
	}
	steps, err := ghworkflow.RunSteps(&spec)
	if err != nil {
		return nil, workflowTimeoutReadError(rel, data, fmt.Errorf("read run steps: %w", err))
	}
	defaults := workflowCallDefaults(&spec)
	var out []string
	var failures []error
	for _, run := range steps {
		findings, err := workflowRunTimeouts(rel, &spec, run, defaults)
		if err != nil {
			failures = append(failures, err)
		}
		out = append(out, findings...)
	}
	return out, errors.Join(failures...)
}

// workflowRunTimeouts checks candidate-bearing steps under their resolved interpreter.
func workflowRunTimeouts(rel string, spec *ghworkflow.Spec, run ghworkflow.RunStep, defaults map[string]exprValue) ([]string, error) {
	script := strings.ReplaceAll(run.Step.Run, "\r\n", "\n")
	location := timeoutSource{file: rel, line: func(n int) int { return hiss.WorkflowRunLine(run.Step, n+1) }}
	candidate := rawTestCandidate(script)
	if candidate == nil {
		return nil, nil
	}
	shell := ghworkflow.StepShell(spec, run.Job, run.Step)
	if shell != "bash" && shell != "sh" {
		return nil, location.refuse(script, candidate[0], fmt.Sprintf("resolved shell %q must be bash or sh", shell))
	}
	source, ok := hiss.WorkflowShellCommandSource(script, maxTimeoutWorkflowLines)
	if !ok {
		return nil, location.refuse(script, candidate[0], "unreadable shell run script or shell reader bound")
	}
	return location.check(script, source, defaults)
}
