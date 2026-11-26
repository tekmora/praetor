// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/util"
)

// Candidate recognition is deliberately broader than proof. Quotes, escapes and line
// splices can split the literal names. After a leading option, keep looking for test
// without assuming that the option or its operand belongs to the supported Go grammar.
const (
	wordJoint = `(?:\\\r?\n|['"\\])*`
	wordSpace = `(?:[ \t]|\\\r?\n)+`

	// A flag can carry an attached value or consume one more word. Keep quoted
	// operands together and ordinary shell command separators outside the sequence.
	wordPart = `(?:\$\([^\r\n]*\)|\$\{[^}\r\n]*\}|[^ \t\r\n'"\\;&|]+|'[^']*'|"[^"]*"|\\(?:\r?\n|.))`
	flagWord = wordSpace + wordJoint + `(?:-|\$)` + wordPart + `*` + wordJoint
)

// candidateWord admits shell quotes, escapes and line splices between every literal character.
func candidateWord(name string) string {
	characters := strings.Split(name, "")
	for i, char := range characters {
		characters[i] = regexp.QuoteMeta(char)
	}
	return strings.Join(characters, wordJoint)
}

var (
	goWord   = candidateWord("go") + wordJoint + "(?:" + candidateWord(".exe") + wordJoint + ")?"
	testWord = candidateWord("test")
)

// testInvocation captures a Go command head or a Make wrapper independently of shell parsing.
var testInvocation = regexp.MustCompile(`(?:^|[[:space:]/\\'"$,=;&|<>()\x60])[ @+\t-]*(` +
	goWord + `(?:` + flagWord + `(?:` + wordSpace + wordPart + `+)?)*` +
	`(?:[ \t]*[<>]` + wordPart + `*)?` + wordSpace + wordJoint + testWord + `)` +
	wordJoint + `(?:$|[[:space:],;&|<>()\x60])|(\$\(GO_TEST\)|\$\{GO_TEST\})`)

var (
	literalGoDirectory = regexp.MustCompile(`^[[:alnum:]_./:\\ +~-]+$`)
	makeVariable       = regexp.MustCompile(`^\$(?:\([[:alnum:]_]+\)|\{[[:alnum:]_]+\})$`)
)

// timeoutSource maps a shell reader's zero-based lines to a workflow or Makefile.
type timeoutSource struct {
	file        string
	line        func(int) int
	literals    map[int]int
	assignments map[string]string
	wrapper     timeoutWrapper
	packageName string
}

// rawTestCandidate returns the candidate's byte interval, excluding its word delimiters.
func rawTestCandidate(script string) []int {
	match := testInvocation.FindStringSubmatchIndex(script)
	if match == nil {
		return nil
	}
	if match[2] >= 0 {
		return match[2:4]
	}
	return match[4:6]
}

// unverifiableTestInvocation names one candidate that could not be checked against the duration policy.
func unverifiableTestInvocation(file string, line int, reason string) error {
	return fmt.Errorf("[FAIL] %s: %s:%d unverifiable test invocation: %s", testTimeoutGate, file, line, reason)
}

// refuse reports a raw candidate at its physical line, even when no command could be parsed.
func (s timeoutSource) refuse(script string, offset int, reason string) error {
	return unverifiableTestInvocation(s.file, s.line(strings.Count(script[:offset], "\n")), reason)
}

// makefileTimeouts checks the bounded Make reader's recipes and keeps all independent findings.
func makefileTimeouts(text string) ([]string, error) {
	file, err := util.MakefileRecipes(text, maxTimeoutWorkflowLines)
	if err != nil {
		if !testInvocation.MatchString(strings.NewReplacer("\\\r\n\t", "", "\\\n\t", "").Replace(text)) {
			return nil, nil
		}
		return nil, fmt.Errorf("[FAIL] %s: %w", testTimeoutGate, err)
	}
	var findings []string
	var failures []error
	oneShell := file.Targets[".ONESHELL"] || util.MakefileHasTarget(text, ".ONESHELL")
	assignments, defaultDirectory := util.MakefileSimpleAssignments(text, "CURDIR")
	source := timeoutSource{
		file:        "Makefile",
		assignments: assignments,
		wrapper:     readTimeoutWrapper(assignments["GO_TEST"], defaultDirectory),
	}
	for _, recipe := range file.Recipes {
		if oneShell {
			recipe.Unresolved = ".ONESHELL recipes share a shell"
		}
		result, err := source.recipeTimeouts(recipe)
		if err != nil {
			failures = append(failures, err)
		}
		findings = append(findings, result...)
	}
	return findings, errors.Join(failures...)
}

// recipeTimeouts checks only logical recipe lines holding a raw test candidate.
func (s timeoutSource) recipeTimeouts(recipe util.MakefileRecipe) ([]string, error) {
	script := recipe.Text
	candidate := rawTestCandidate(script)
	if candidate == nil {
		return nil, nil
	}
	s.literals = recipe.LiteralSpans
	s.line = func(n int) int { return recipe.Line + n + 1 }
	if recipe.Unresolved != "" {
		return nil, s.refuse(script, candidate[0], recipe.Unresolved)
	}
	for start, end := range recipe.LiteralSpans {
		if !makeVariable.MatchString(script[start:end]) {
			return nil, s.refuse(script, candidate[0], "unexpanded Make construct in recipe")
		}
	}
	source, ok := hiss.ReadShellCommandSource(script, maxTimeoutWorkflowLines, recipe.LiteralSpans)
	if !ok {
		return nil, s.refuse(script, candidate[0], "unreadable shell recipe or shell reader bound")
	}
	return s.check(script, source, nil)
}

// check erases only proven program words and comments from a copy of the source. Any
// remaining candidate is unresolved, including a second occurrence on the same line.
func (s timeoutSource) check(script string, source hiss.ShellCommandSource, defaults map[string]exprValue) ([]string, error) {
	binding := initialPackageBinding.FindStringSubmatchIndex(script)
	remaining := []byte(script)
	for _, span := range source.Comments {
		blankTimeoutSpan(remaining, span)
	}
	var findings []string
	for _, command := range source.Commands {
		long, matched, reason := s.checkCommand(script, command, binding, defaults)
		if reason != "" {
			return nil, s.refuse(script, command.Words[0].Span[0], reason)
		}
		if !matched {
			continue
		}
		findings = append(findings, long...)
		blankTimeoutSpan(remaining, command.Words[0].Span)
	}
	raw := string(remaining)
	if at := rawTestCandidate(raw); at != nil {
		return nil, s.refuse(script, at[0], unresolvedTestReason(raw, at))
	}
	return findings, nil
}

// checkCommand validates a candidate's head, redirections and argument roles at its use site.
func (s timeoutSource) checkCommand(script string, command hiss.ShellCodeCommand, binding []int, defaults map[string]exprValue) ([]string, bool, string) {
	args, reason := s.commandArgs(script, command)
	if args == nil || reason != "" {
		return nil, false, reason
	}
	args, reason = s.literalTimeoutArgs(script, command, args)
	if reason != "" {
		return nil, true, reason
	}
	if binding != nil && binding[1] == command.Words[0].Span[0] {
		s.packageName = script[binding[2]:binding[3]]
	}
	where := fmt.Sprintf("%s:%d", s.file, s.line(command.Line))
	findings, reason := s.explicitTimeouts(where, args, defaults)
	return findings, true, reason
}

// commandArgs recognizes adoption's literal exec recipe head after the shell reader has
// resolved exec. A Make variable in program position still requires the checked wrapper.
func (s timeoutSource) commandArgs(script string, command hiss.ShellCodeCommand) ([]hiss.ShellCodeWord, string) {
	words := command.Words
	if s.file == "Makefile" && len(words) >= 2 && script[:words[1].Span[1]] == "exec 'go' 'test'" {
		return words[2:], ""
	}
	program := words[0]
	if (program.Text == "$(GO_TEST)" || program.Text == "${GO_TEST}") && s.literals[program.Span[0]] == program.Span[1] {
		return s.wrapper.arguments(words[1:])
	}
	return goTestArgs(words), ""
}

// blankTimeoutSpan removes the evidence for one accounted occurrence without shifting offsets.
func blankTimeoutSpan(script []byte, span [2]int) {
	for i := span[0]; i < span[1]; i++ {
		if script[i] != '\n' {
			script[i] = ' '
		}
	}
}

// unresolvedTestReason describes the raw candidate that failed to match a command head.
func unresolvedTestReason(raw string, at []int) string {
	if at[1] < len(raw) && strings.ContainsRune("<>&|;()", rune(raw[at[1]])) {
		return "operator attached to an invocation word"
	}
	if strings.Contains(raw[at[0]:at[1]], "-") {
		return "unsupported Go global flag or operand (expected -C dir)"
	}
	return "raw test tokens do not resolve to a literal command"
}

// literalTimeoutArgs admits an optional trailing stdout redirection and descriptor duplication,
// as used by the portability workflow. Remaining operators must be separated from command words.
func (s timeoutSource) literalTimeoutArgs(script string, command hiss.ShellCodeCommand, args []hiss.ShellCodeWord) ([]hiss.ShellCodeWord, string) {
	start := command.Words[0].Span[0]
	last := command.Words[len(command.Words)-1].Span[1]
	const blanks = " \t\n"
	if (start > 0 && strings.IndexByte(blanks, script[start-1]) < 0) ||
		(last < len(script) && strings.IndexByte(blanks, script[last]) < 0) {
		return nil, "operator attached to an invocation word"
	}
	end := s.timeoutArgEnd(args)
	for _, word := range args[:end] {
		if strings.ContainsAny(word.Code, "<>") {
			return nil, "unsupported redirection or operator attached to an invocation word"
		}
	}
	return args[:end], ""
}

// timeoutArgEnd removes the literal redirection suffix supported on portability test commands.
func (s timeoutSource) timeoutArgEnd(args []hiss.ShellCodeWord) int {
	end := len(args)
	if end > 0 && args[end-1].Text == "2>&1" {
		end--
	}
	if end >= 2 && args[end-2].Text == ">" && s.flagValue(args[end-1]) {
		end -= 2
	}
	return end
}
