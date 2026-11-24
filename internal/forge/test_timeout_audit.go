// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/util"
	"go.yaml.in/yaml/v3"
)

// testTimeoutGate names the check in its lines.
const testTimeoutGate = "test-timeout"

// testTimeoutBoundMinutes is the go test timeout workflows and Makefile keep per package (#1381).
const testTimeoutBoundMinutes = 30

var (
	// goTestCommand matches workflow text mentioning a Go test invocation.
	goTestCommand = regexp.MustCompile(`\bgo(?:\.exe)?\s+[^;&|]*\btest\b|\$\(GO_TEST\)`)
	// goTimeoutFlag matches a -timeout or --timeout flag on a command line; its value is a whole
	// ${{ ... }} expression, spaces included, or a word.
	goTimeoutFlag = regexp.MustCompile(`(?:^|[\s;&|])--?timeout(?:=|\s+)["']?(\$\{\{[^}]*\}\}|[^"'\s;&|]+)["']?`)
	// inputExpression matches a value that is exactly ${{ inputs.<id> }}.
	inputExpression = regexp.MustCompile(`^\$\{\{\s*inputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$`)
)

const (
	maxTimeoutWorkflowLines = 20000
	maxMatchesPerLine       = 16
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
// bound, naming the file, line and value of each timeout without a live exception.
func AuditTestTimeouts(ctx context.Context, opts TestTimeoutOptions) (string, error) {
	files, err := readTestTimeoutFiles(ctx, opts.Root)
	if err != nil {
		return "", err
	}
	entries := config.ExceptionsFor(opts.Exceptions, config.ExceptionRuleTestTimeout)
	used := make([]bool, len(entries))
	var findings, excepted []string
	for _, file := range files {
		rel := file.Name
		long, err := fileTimeouts(file)
		if err != nil {
			return "", err
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
	for i, entry := range entries {
		if !used[i] {
			findings = append(findings, fmt.Sprintf("[FAIL] %s: the exceptions entry for %s excuses nothing, because the file keeps the bound; remove it", testTimeoutGate, entry.Target()))
		}
	}
	if len(findings) > 0 {
		return "", errors.New(strings.Join(findings, "\n"))
	}
	return strings.Join(append(excepted, "[PASS] test-timeout"), "\n"), nil
}

// fileTimeouts returns the long go test timeouts of one audited file: the root Makefile by joined
// logical lines, a workflow line by line with its input defaults.
func fileTimeouts(file workflowFile) ([]string, error) {
	if lines := physicalLines(string(file.Data)); lines > maxTimeoutWorkflowLines {
		return nil, fmt.Errorf("[FAIL] %s: %s has %d lines, above the %d-line scan bound; lines past it would not be audited",
			testTimeoutGate, file.Name, lines, maxTimeoutWorkflowLines)
	}
	if file.Name == "Makefile" {
		return makefileTimeouts(string(file.Data))
	}
	return longTimeouts(file.Name, string(file.Data), timeoutInputDefaults(file.Data)), nil
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

// makefileTimeouts asks Make's reader for recipe invocations and the shared shell reader
// for each command and its source-aligned arguments.
func makefileTimeouts(text string) ([]string, error) {
	recipes, err := util.MakefileRecipes(text, maxTimeoutWorkflowLines)
	if err != nil {
		return nil, fmt.Errorf("[FAIL] %s: %w", testTimeoutGate, err)
	}
	var out []string
	for _, recipe := range recipes {
		commands, ok := hiss.ShellCodeCommands(recipe.Text, maxTimeoutWorkflowLines, recipe.LiteralSpans)
		if !ok {
			return nil, fmt.Errorf("[FAIL] %s: Makefile:%d has unreadable shell recipe", testTimeoutGate, recipe.Line+1)
		}
		for _, command := range commands {
			where := fmt.Sprintf("Makefile:%d", recipe.Line+command.Line+1)
			out = append(out, makefileCommandTimeouts(where, command.Words)...)
		}
	}
	return out, nil
}

func makefileCommandTimeouts(where string, words []hiss.ShellCodeWord) []string {
	args := goTestRecipeArgs(words)
	var findings []string
	matches := 0
	for i := 0; i < len(args) && matches < maxMatchesPerLine; i++ {
		value, next, ok := makefileTimeoutValue(args, i)
		i = next
		if !ok {
			continue
		}
		matches++
		if finding := judgeTimeout(where, value, nil); finding != "" {
			findings = append(findings, finding)
		}
	}
	return findings
}

func goTestRecipeArgs(words []hiss.ShellCodeWord) []hiss.ShellCodeWord {
	program := words[0]
	if program.Opaque && (program.Text == "$(GO_TEST)" || program.Text == "${GO_TEST}") {
		return words[1:]
	}
	name := path.Base(program.Value)
	if name != "go" && name != "go.exe" {
		return nil
	}
	i := 1
	for i+1 < len(words) && words[i].Value == "-C" {
		i += 2
	}
	if i < len(words) && words[i].Value == "test" {
		return words[i+1:]
	}
	return nil
}

func makefileTimeoutValue(args []hiss.ShellCodeWord, i int) (value string, next int, ok bool) {
	flag, value, hasEquals := strings.Cut(args[i].Value, "=")
	if flag != "-timeout" && flag != "--timeout" {
		return "", i, false
	}
	if hasEquals {
		return value, i, true
	}
	if i+1 < len(args) {
		return args[i+1].Value, i + 1, true
	}
	return "", i, false
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

// timeoutInputDefaults returns the literal workflow_call input defaults of a workflow
// (workflowCallDefaults), by input id; a workflow that does not parse has none, so an input it
// names stays unreadable.
func timeoutInputDefaults(data []byte) map[string]exprValue {
	var spec workflowSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil
	}
	return workflowCallDefaults(&spec)
}

// isFullLineComment reports whether a workflow line starts with # after optional blanks.
func isFullLineComment(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	return trimmed != "" && trimmed[0] == '#'
}

// checkGoTestTimeouts checks a go test command line for -timeout flags.
func checkGoTestTimeouts(rel string, n int, line string, defaults map[string]exprValue) []string {
	if isFullLineComment(line) {
		return nil
	}
	if !goTestCommand.MatchString(line) {
		return nil
	}
	matches := goTimeoutFlag.FindAllStringSubmatch(line, maxMatchesPerLine)
	var out []string
	for i := 0; i < len(matches) && i < maxMatchesPerLine; i++ {
		if finding := judgeTimeout(fmt.Sprintf("%s:%d", rel, n+1), matches[i][1], defaults); finding != "" {
			out = append(out, finding)
		}
	}
	return out
}

// judgeTimeout returns the finding for one -timeout value at where, "" within the bound. A value
// ${{ inputs.<id> }} is judged by that input's workflow_call default; an input without a
// literal default the gate can read is unreadable, as any other value it cannot parse.
func judgeTimeout(where, raw string, defaults map[string]exprValue) string {
	value, shown := raw, raw
	if input := inputExpression.FindStringSubmatch(raw); input != nil {
		def, ok := defaults[input[1]]
		if !ok {
			return fmt.Sprintf("[FAIL] %s: %s sets %s, an unreadable timeout: the input has no default this gate can read", testTimeoutGate, where, raw)
		}
		value, shown = def.text, fmt.Sprintf("%s (default %s)", raw, def.text)
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Sprintf("[FAIL] %s: %s sets %s, an unreadable timeout", testTimeoutGate, where, shown)
	}
	if d > time.Duration(testTimeoutBoundMinutes)*time.Minute {
		return fmt.Sprintf("[FAIL] %s: %s sets %s, above the %dm bound", testTimeoutGate, where, shown, testTimeoutBoundMinutes)
	}
	return ""
}

// longTimeouts returns one line per go test -timeout above the bound or unreadable in rel; a job's
// timeout-minutes is not this gate's subject (decision engine-timeout-audit-scope-20261018).
// defaults are the workflow's workflow_call input defaults (timeoutInputDefaults).
func longTimeouts(rel, text string, defaults map[string]exprValue) []string {
	if !goTestCommand.MatchString(text) {
		return nil
	}
	lines := strings.Split(text, "\n")
	var out []string
	for n := 0; n < len(lines) && n < maxTimeoutWorkflowLines; n++ {
		out = append(out, checkGoTestTimeouts(rel, n, lines[n], defaults)...)
	}
	return out
}
