// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
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
	"go.yaml.in/yaml/v3"
)

// testTimeoutGate names the check in its lines.
const testTimeoutGate = "test-timeout"

// testTimeoutBoundMinutes is the go test timeout workflows and Makefile keep per package (#1381).
const testTimeoutBoundMinutes = 30

var (
	// goTestCommand also recognizes the Makefile's sandboxed GO_TEST command.
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

// makefileScanOptions tunes makefileScanner; only scanMakefileTimeouts supplies non-defaults
// for the mutant tests.
type makefileScanOptions struct {
	splitAtComments         bool
	topLevelCommentContinue bool
	trackShellQuotes        bool
}

// makefileScanner accumulates continued physical Makefile lines into logical commands. Recipe
// lines are physical lines that start with a tab (.RECIPEPREFIX is not read; only the tab rule
// applies). A full-line recipe comment (tab, then # through end) ends at its newline in the shell
// and never absorbs the next line, except when the open logical command still has an unclosed
// shell quote: then the line is shell text and is appended like any continued line. Top-level
// full-line comments (not recipe lines) follow GNU make: a trailing backslash continues the
// comment onto following physical lines until one does not end with a backslash, and that last
// comment line is ignored too.
type makefileScanner struct {
	logical        strings.Builder
	out            []string
	start          int
	continued      bool
	recipeCommand  bool
	opts           makefileScanOptions
	inCommentBlock bool
	lastContLine   string
}

// trailingBackslashCount is how many consecutive backslashes end line (GNU make continuation: odd count continues).
func trailingBackslashCount(line string) int {
	n := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		n++
	}
	return n
}

// lineContinuesAtEOL reports whether line's trailing backslash count is odd (GNU make line splice).
func lineContinuesAtEOL(line string) bool {
	return trailingBackslashCount(line)%2 == 1
}

// continuationBackslashJoinsWord reports whether an EOL continuation backslash leaves the shell inside
// a word so the next physical line continues that token (backslash immediately after a non-blank byte).
func continuationBackslashJoinsWord(line string) bool {
	if !lineContinuesAtEOL(line) {
		return false
	}
	spliceAt := len(line) - 1
	if spliceAt == 0 {
		return false
	}
	prev := line[spliceAt-1]
	return prev != ' ' && prev != '\t'
}

// flush checks the accumulated logical line at its starting line number and resets the buffer.
func (s *makefileScanner) flush() {
	s.out = append(s.out, checkGoTestTimeouts("Makefile", s.start, s.logical.String(), nil)...)
	s.logical.Reset()
	s.continued = false
	s.recipeCommand = false
	s.lastContLine = ""
}

// isRecipeLine reports whether line is a Makefile recipe line (default recipe prefix is tab).
func isRecipeLine(line string) bool {
	return line != "" && line[0] == '\t'
}

// advanceShellQuoteState updates single/double-quote shell state at text[i]; it skips an escaped
// byte and reports the next index to read.
func advanceShellQuoteState(text string, i int, inSingle, inDouble *bool) int {
	c := text[i]
	if *inSingle {
		if c == '\'' {
			*inSingle = false
		}
		return i + 1
	}
	if *inDouble {
		if c == '\\' && i+1 < len(text) {
			return i + 2
		}
		if c == '"' {
			*inDouble = false
		}
		return i + 1
	}
	switch c {
	case '\'':
		*inSingle = true
	case '"':
		*inDouble = true
	case '\\':
		if i+1 < len(text) {
			return i + 2
		}
	}
	return i + 1
}

// hasOpenShellQuote reports whether text ends inside an unclosed single- or double-quoted span,
// using sh quoting rules. Each step advances at least one byte, so the loop reads at most
// len(text) bytes (HISS-02): the logical command is already bounded by the snapshot reader.
func hasOpenShellQuote(text string) bool {
	inSingle, inDouble := false, false
	for i := 0; i < len(text); {
		i = advanceShellQuoteState(text, i, &inSingle, &inDouble)
	}
	return inSingle || inDouble
}

// recipeCommentEndsCommand reports whether line is a recipe full-line comment that ends the
// current logical command instead of appending shell text.
func (s *makefileScanner) recipeCommentEndsCommand(line string) bool {
	if !s.opts.splitAtComments || !isFullLineComment(line) || !isRecipeLine(line) {
		return false
	}
	if s.opts.trackShellQuotes && hasOpenShellQuote(s.logical.String()) {
		return false
	}
	if s.continued && continuationBackslashJoinsWord(s.lastContLine) {
		return false
	}
	return true
}

// trimContinuationSuffix removes one logical continuation backslash from line's end (odd trailing count).
func trimContinuationSuffix(line string) string {
	if !lineContinuesAtEOL(line) {
		return line
	}
	return line[:len(line)-1]
}

// appendPhysicalLine adds one physical line to the open logical command.
func (s *makefileScanner) appendPhysicalLine(line string) {
	if !s.continued {
		return
	}
	if lineContinuesAtEOL(line) {
		s.logical.WriteString(trimContinuationSuffix(line))
		s.logical.WriteByte(' ')
		s.lastContLine = line
		return
	}
	s.logical.WriteString(line)
	s.flush()
}

// startPhysicalLine begins a new logical command at line number n.
func (s *makefileScanner) startPhysicalLine(n int, line string) {
	s.start = n
	s.recipeCommand = isRecipeLine(line)
	if lineContinuesAtEOL(line) {
		s.logical.WriteString(trimContinuationSuffix(line))
		s.logical.WriteByte(' ')
		s.continued = true
		s.lastContLine = line
		return
	}
	s.logical.WriteString(line)
	s.flush()
}

// addLine appends one physical line (without CR) to the current logical command or ends it at a
// comment boundary.
func (s *makefileScanner) addLine(n int, line string) {
	if s.recipeCommentEndsCommand(line) {
		if s.continued {
			s.flush()
		}
		return
	}
	if s.continued {
		s.appendPhysicalLine(line)
		return
	}
	s.startPhysicalLine(n, line)
}

// skipTopLevelCommentBlock updates inCommentBlock for non-recipe full-line comments and returns
// whether the current physical line should be ignored.
func (s *makefileScanner) skipTopLevelCommentBlock(line string) bool {
	if s.continued && s.recipeCommand {
		return false
	}
	if s.opts.topLevelCommentContinue && s.inCommentBlock {
		if lineContinuesAtEOL(line) {
			return true
		}
		s.inCommentBlock = false
		return true
	}
	if isRecipeLine(line) || !isFullLineComment(line) {
		return false
	}
	if s.continued {
		s.flush()
	}
	s.inCommentBlock = s.opts.topLevelCommentContinue && lineContinuesAtEOL(line)
	return true
}

// unfinishedContinuation reports whether line n's trailing backslash has no following physical line
// within the scan bound.
func unfinishedContinuation(lines []string, n int) bool {
	return n+1 >= len(lines) || (n+2 == len(lines) && lines[n+1] == "") || n+1 >= maxTimeoutWorkflowLines
}

// makefileTimeouts joins continued physical lines and retains their first line number. See
// makefileScanner for recipe versus top-level comment rules and the open-quote exception.
func makefileTimeouts(text string) ([]string, error) {
	return scanMakefileTimeouts(text, makefileScanOptions{
		splitAtComments:         true,
		topLevelCommentContinue: true,
		trackShellQuotes:        true,
	})
}

// scanMakefileTimeouts implements makefileTimeouts; non-default option fields exist only for
// mutant tests (splitAtComments, topLevelCommentContinue, trackShellQuotes).
func scanMakefileTimeouts(text string, opts makefileScanOptions) ([]string, error) {
	lines := strings.Split(text, "\n")
	scanner := makefileScanner{opts: opts}
	for n := 0; n < len(lines) && n < maxTimeoutWorkflowLines; n++ {
		line := strings.TrimSuffix(lines[n], "\r")
		if lineContinuesAtEOL(line) && unfinishedContinuation(lines, n) {
			return nil, fmt.Errorf("[FAIL] %s: Makefile:%d has an unfinished continuation", testTimeoutGate, n+1)
		}
		if scanner.skipTopLevelCommentBlock(line) {
			continue
		}
		scanner.addLine(n, line)
	}
	return scanner.out, nil
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

// isFullLineComment reports whether line is only a Makefile, shell or YAML comment: leading
// whitespace then # through end. A command with a trailing # comment is not a comment line.
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
