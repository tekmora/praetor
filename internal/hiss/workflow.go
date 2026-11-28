// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hiss

import (
	slashpath "path"
	"regexp"
	"strings"

	"github.com/cordanaLLM/praetor/internal/ghworkflow"
)

// GitHub Actions workflows.
//
// A run: block is a shell script that runs with the job's token, often with the repository's
// most sensitive commands, so the shell rules apply to it as to a script file (#618). The
// scanner reads every document GitHub runs as a workflow, a YAML file directly in
// .github/workflows, through the one workflow model the forge audits read too
// (internal/ghworkflow), and resolves each run: step's shell the way GitHub does: the step's
// shell:, the job's and then the workflow's defaults.run.shell, then the runner's default
// (ghworkflow.StepShell). A block whose shell the shell scanner reads (sh, bash, dash, ash) is
// scanned with the shell rules (scanShellLines). Its ${{ }} expressions are blanked first,
// keeping its line breaks: GitHub substitutes them before the shell starts, so their text is
// not shell. A finding is reported against the workflow file: in a literal block (run: |) at
// the line it sits on, in any other style at the line the value starts on, since folding and
// escapes lose the mapping.
//
// Every other block is counted in ScanCoverage.UnscannedRunBlocks under its shell (pwsh,
// python, cmd, the command of a custom template) or as unresolved when the shell is decided only
// when the workflow runs (an expression, or a runner whose labels name no single operating
// system). So is a block of a read shell that the shell scanner declines, one past
// maxWorkflowRunBlocks in its file and one longer than maxRunBlockBytes. None of them reads as
// clean. A document the workflow model refuses (malformed, or past its job or step bounds) is
// declined whole and counted as unscanned github-actions source.
//
// A run: block has no interpreter line: GitHub starts its shell itself (bash -e, bash
// --noprofile --norc -eo pipefail for shell: bash, sh -e), so HISS-07's strict-mode rule, which
// holds a script with an interpreter line to set -eu, is not decided for a block.

const (
	// workflowLanguageName is the language the coverage record names a workflow file under.
	workflowLanguageName = "github-actions"
	// unresolvedShell labels a block whose shell is decided only when the workflow runs.
	unresolvedShell = "unresolved"
	// customShell labels a block whose custom shell command cannot serve as a coverage key.
	customShell = "custom"
	// maxWorkflowRunBlocks bounds the run: blocks scanned in one workflow file (HISS-02).
	maxWorkflowRunBlocks = 512
	// maxRunBlockBytes bounds one run: block (HISS-02). The bound is praetor's own, not a GitHub
	// limit. GitHub's 21,000-character limit is the maximum length of an expression; it reaches a
	// run: value only through the ${{ }} expressions the value holds.
	maxRunBlockBytes = 64 << 10
)

// workflowExpressionSpans returns the byte spans of complete Actions expressions.
// closed is false if an opener has no closing braces outside a string.
func workflowExpressionSpans(script string) (spans [][2]int, closed bool) {
	const opener = "${{"
	for from := 0; from < len(script); {
		offset := strings.Index(script[from:], opener)
		if offset < 0 {
			return spans, true
		}
		start := from + offset
		end := workflowExpressionEnd(script, start+len(opener))
		if end < 0 {
			return spans, false
		}
		spans = append(spans, [2]int{start, end})
		from = end
	}
	return spans, true
}

// workflowExpressionEnd returns the exclusive end of an expression, or -1.
func workflowExpressionEnd(script string, start int) int {
	quoted := false
	for i := start; i < len(script); i++ {
		switch script[i] {
		case '\'':
			if quoted && i+1 < len(script) && script[i+1] == '\'' {
				i++
				continue
			}
			quoted = !quoted
		case '}':
			if !quoted && i+1 < len(script) && script[i+1] == '}' {
				return i + 2
			}
		}
	}
	return -1
}

// shellLabel matches a shell name fit to key the coverage record.
var shellLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]*$`)

// FixturePath returns the slash-separated path below a scan root at which a file named name is
// read as language: a GitHub Actions workflow only directly in .github/workflows, a file of any
// other language wherever it sits, so at the root. The HISS-20 corpus replay stages each
// fixture there (internal/hisscoverage).
func FixturePath(language, name string) string {
	if language == workflowLanguageName {
		return slashpath.Join(ghworkflow.Dir, name)
	}
	return name
}

// workflowLanguage reads the run: blocks of GitHub Actions workflows with the shell rules.
type workflowLanguage struct{}

// handles claims no extension: a YAML file is a workflow only where GitHub reads one.
func (workflowLanguage) handles(string) bool { return false }

func (workflowLanguage) name() string { return workflowLanguageName }

func (workflowLanguage) candidate(rel, _ string) bool { return ghworkflow.IsWorkflowPath(rel) }

// claims takes every candidate: GitHub runs every YAML document in .github/workflows, so one the
// model cannot read is unscanned workflow source, not an unrelated file.
func (workflowLanguage) claims(sourceFile) bool { return true }

func (workflowLanguage) fileBound() int { return ghworkflow.MaxFiles }

func (workflowLanguage) scan(src sourceFile, rep *ScanReport, opts ScanOptions) bool {
	spec, err := ghworkflow.Parse(src.data)
	if err != nil {
		return false
	}
	steps, err := ghworkflow.RunSteps(&spec)
	if err != nil {
		return false
	}
	file := &ScanReport{}
	for i := 0; i < len(steps); i++ {
		shell := ghworkflow.StepShell(&spec, steps[i].Job, steps[i].Step)
		if i >= maxWorkflowRunBlocks || !scanRunBlock(src.rel, steps[i].Step, shell, file, opts) {
			rep.Coverage.recordUnscannedRunBlock(runBlockLabel(shell))
		}
	}
	recordInLineOrder(rep, file)
	return true
}

// scanRunBlock applies the shell rules to one step's run: block, started by shell, and records
// its findings in file at their workflow lines. It reports false for a block it did not read: a
// shell the shell scanner does not read, a block past the byte bound or holding a NUL byte, and
// one the shell scanner declined.
func scanRunBlock(rel string, step *ghworkflow.Step, shell string, file *ScanReport, opts ScanOptions) bool {
	if !shellLanguages[shell] || len(step.Run) > maxRunBlockBytes || strings.IndexByte(step.Run, 0) >= 0 {
		return false
	}
	blanked, closed := blankExpressions(step.Run)
	if !closed {
		return false
	}
	block := &ScanReport{}
	script := sourceFile{rel: rel, data: []byte(blanked)}
	if !scanShellLines(rel, script.lfLines(), shellInterp{known: true, bash: shell == "bash"}, block, opts) {
		return false
	}
	for _, v := range block.Violations {
		recordViolation(file, v.RuleID, v.FilePath, WorkflowRunLine(step, v.LineNumber), v.Symbol, v.Message)
	}
	return true
}

// blankExpressions replaces complete expressions with spaces while preserving
// byte offsets and line breaks. It declines scripts with an unclosed expression.
func blankExpressions(script string) (string, bool) {
	spans, closed := workflowExpressionSpans(script)
	if !closed {
		return "", false
	}
	if len(spans) == 0 {
		return script, true
	}
	blanked := []byte(script)
	for _, span := range spans {
		for i := span[0]; i < span[1]; i++ {
			if blanked[i] == '\n' || (blanked[i] == '\r' && i+1 < len(script) && script[i+1] == '\n') {
				continue
			}
			blanked[i] = ' '
		}
	}
	return string(blanked), true
}

// WorkflowShellCommandSource reads a decoded run script with expressions kept as opaque shell word
// fragments. This retains the source spelling of timeout values without parsing expressions as shell.
func WorkflowShellCommandSource(script string, maxLines int) (ShellCommandSource, bool) {
	return workflowShellCommandSource(script, maxLines, false)
}

// WorkflowShellCommandSourceForShell reads a run script with opaque Actions expressions.
// Only a resolved bash selects Bash heredoc semantics; all other values use the portable check.
func WorkflowShellCommandSourceForShell(script string, maxLines int, shell string) (ShellCommandSource, bool) {
	return workflowShellCommandSource(script, maxLines, shell != "bash")
}

// workflowShellCommandSource normalizes CRLF to LF, returns false if workflow expression spans are unclosed, and otherwise parses the script with those spans masked as literals.
func workflowShellCommandSource(script string, maxLines int, portableHeredoc bool) (ShellCommandSource, bool) {
	script = strings.ReplaceAll(script, "\r\n", "\n")
	spans, closed := workflowExpressionSpans(script)
	if !closed {
		return ShellCommandSource{}, false
	}
	literals := make(map[int]int, len(spans))
	for _, span := range spans {
		literals[span[0]] = span[1]
	}
	return readShellCommandSource(script, maxLines, literals, portableHeredoc)
}

// WorkflowRunLine maps one-based line n of a step's script to the workflow line: in a literal
// block the line after the indicator is line 1, and any other style is reported at the line its
// value starts on.
func WorkflowRunLine(step *ghworkflow.Step, n int) int {
	if step.RunLiteral {
		return step.RunLine + n
	}
	return step.RunLine
}

// runBlockLabel names an unscanned block's shell for the coverage record: the shell itself,
// unresolved when the workflow alone does not decide it, and custom for a command that does not
// fit a coverage key.
func runBlockLabel(shell string) string {
	switch {
	case shell == "":
		return unresolvedShell
	case len(shell) > maxCoverageExtensionBytes || !shellLabel.MatchString(shell):
		return customShell
	}
	return shell
}
