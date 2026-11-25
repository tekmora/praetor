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
	flagWord = wordSpace + wordJoint + `-` + wordPart + `*` + wordJoint
	goWord   = `g` + wordJoint + `o` + wordJoint + `(?:\.exe` + wordJoint + `)?`
	testWord = `t` + wordJoint + `e` + wordJoint + `s` + wordJoint + `t`
)

// testInvocation captures a Go command head or a Make wrapper independently of shell parsing.
var testInvocation = regexp.MustCompile(`(?:^|[[:space:]/\\'"$,=;&|<>()\x60])[ @+\t-]*(` +
	goWord + `(?:` + flagWord + `(?:` + wordSpace + wordPart + `+)?)*` +
	`(?:[ \t]*[<>]` + wordPart + `*)?` + wordSpace + wordJoint + testWord + `)` +
	wordJoint + `(?:$|[[:space:],;&|<>()\x60])|(\$\(GO_TEST\)|\$\{GO_TEST\})`)

var (
	literalGoDirectory = regexp.MustCompile(`^[[:alnum:]_./:\\ +~-]+$`)
	makeVariable       = regexp.MustCompile(`^\$(?:\([[:alnum:]_]+\)|\{[[:alnum:]_]+\})$`)
	quotedTestOperand  = regexp.MustCompile(`^(?:'[^']*'|(?:--?[[:alnum:]_-]+=)?"\$(?:[[:alpha:]_][[:alnum:]_]*|\{[[:alpha:]_][[:alnum:]_]*(?:\[@\])?\})")$`)
)

// timeoutSource maps a shell reader's zero-based lines to a workflow or Makefile.
type timeoutSource struct {
	file     string
	line     func(int) int
	literals map[int]int
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
	for _, recipe := range file.Recipes {
		if oneShell {
			recipe.Unresolved = ".ONESHELL recipes share a shell"
		}
		result, err := recipeTimeouts(recipe)
		if err != nil {
			failures = append(failures, err)
		}
		findings = append(findings, result...)
	}
	return findings, errors.Join(failures...)
}

// recipeTimeouts checks only logical recipe lines holding a raw test candidate.
func recipeTimeouts(recipe util.MakefileRecipe) ([]string, error) {
	script := recipe.Text
	candidate := rawTestCandidate(script)
	if candidate == nil {
		return nil, nil
	}
	location := timeoutSource{file: "Makefile", literals: recipe.LiteralSpans, line: func(n int) int { return recipe.Line + n + 1 }}
	if recipe.Unresolved != "" {
		return nil, location.refuse(script, candidate[0], recipe.Unresolved)
	}
	for start, end := range recipe.LiteralSpans {
		if !makeVariable.MatchString(script[start:end]) {
			return nil, location.refuse(script, candidate[0], "unexpanded Make construct in recipe")
		}
	}
	source, ok := hiss.ReadShellCommandSource(script, maxTimeoutWorkflowLines, recipe.LiteralSpans)
	if !ok {
		return nil, location.refuse(script, candidate[0], "unreadable shell recipe or shell reader bound")
	}
	return location.check(script, source, nil)
}

// check erases only proven program words and comments from a copy of the source. Any
// remaining candidate is unresolved, including a second occurrence on the same line.
func (s timeoutSource) check(script string, source hiss.ShellCommandSource, defaults map[string]exprValue) ([]string, error) {
	remaining := []byte(script)
	for _, span := range source.Comments {
		blankTimeoutSpan(remaining, span)
	}
	var findings []string
	for _, command := range source.Commands {
		args := s.commandArgs(command)
		if args == nil {
			continue
		}
		args, reason := literalTimeoutArgs(script, command, args)
		if reason != "" {
			return nil, s.refuse(script, command.Words[0].Span[0], reason)
		}
		where := fmt.Sprintf("%s:%d", s.file, s.line(command.Line))
		long, reason := s.explicitTimeouts(where, args, defaults)
		if reason != "" {
			return nil, s.refuse(script, command.Words[0].Span[0], reason)
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

// commandArgs accepts the wrapper only when Make identified the whole program as a variable reference.
func (s timeoutSource) commandArgs(command hiss.ShellCodeCommand) []hiss.ShellCodeWord {
	word := command.Words[0].Text
	if (word == "$(GO_TEST)" || word == "${GO_TEST}") && s.literals[command.Words[0].Span[0]] == command.Words[0].Span[1] {
		return command.Words[1:]
	}
	return goTestArgs(command.Words)
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
func literalTimeoutArgs(script string, command hiss.ShellCodeCommand, args []hiss.ShellCodeWord) ([]hiss.ShellCodeWord, string) {
	start := command.Words[0].Span[0]
	last := command.Words[len(command.Words)-1].Span[1]
	const blanks = " \t\n"
	if (start > 0 && strings.IndexByte(blanks, script[start-1]) < 0) ||
		(last < len(script) && strings.IndexByte(blanks, script[last]) < 0) {
		return nil, "operator attached to an invocation word"
	}
	end := timeoutArgEnd(args)
	for _, word := range args[:end] {
		if strings.ContainsAny(word.Code, "<>") {
			return nil, "unsupported redirection or operator attached to an invocation word"
		}
	}
	return args[:end], ""
}

// timeoutArgEnd removes the literal redirection suffix supported on portability test commands.
func timeoutArgEnd(args []hiss.ShellCodeWord) int {
	end := len(args)
	if end > 0 && args[end-1].Text == "2>&1" {
		end--
	}
	if end >= 2 && args[end-2].Text == ">" && !strings.ContainsAny(args[end-1].Code, "<>") {
		end -= 2
	}
	return end
}

// literalOperand permits literal arguments, quoted shell parameters used as values, and whole
// Make variable operands. A computed flag name or a substitution could supply a timeout.
func (s timeoutSource) literalOperand(word hiss.ShellCodeWord) bool {
	if !strings.ContainsAny(word.Text, "$`") || quotedTestOperand.MatchString(word.Text) {
		return true
	}
	return s.literals[word.Span[0]] == word.Span[1] && makeVariable.MatchString(word.Text)
}

// explicitTimeouts judges every timeout operand and refuses an incomplete flag or bounded read.
func (s timeoutSource) explicitTimeouts(where string, args []hiss.ShellCodeWord, defaults map[string]exprValue) ([]string, string) {
	var findings []string
	matches := 0
	for i := 0; i < len(args); i++ {
		value, next, found := timeoutValue(args, i)
		if !found {
			if !s.literalOperand(args[i]) {
				return nil, "unexpanded argument in test invocation"
			}
			continue
		}
		i = next
		matches++
		if matches > maxTimeoutFlagsPerCommand {
			return nil, "timeout flag count exceeds the reader bound"
		}
		if value == "" {
			return nil, "missing timeout value"
		}
		finding, reason := judgeTimeout(where, value, defaults)
		if reason != "" {
			return nil, reason
		}
		if finding != "" {
			findings = append(findings, finding)
		}
	}
	return findings, ""
}
