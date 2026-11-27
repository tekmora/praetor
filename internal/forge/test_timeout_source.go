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
	wordPart      = `(?:\$\([^\r\n]*\)|\$\{[^}\r\n]*\}|[^ \t\r\n'"\\;&|]+|'[^']*'|"[^"]*"|\\(?:\r?\n|.))`
	flagWord      = wordSpace + wordJoint + `(?:-|\$)` + wordPart + `*` + wordJoint
	makeReference = `\$(?:\([[:alnum:]_.-]+\)|\{[[:alnum:]_.-]+\})`
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
	makeVariable       = regexp.MustCompile(`^` + makeReference + `$`)
	makeReferences     = regexp.MustCompile(makeReference)
)

// timeoutSource maps a shell reader's zero-based lines to a workflow or Makefile.
type timeoutSource struct {
	file              string
	line              func(int) int
	literals          map[int]int
	assignments       map[string]string
	wrappers          map[string]timeoutWrapper
	packageName       string
	workflowShell     bool     // enables Actions-only accounting of environment-file data
	envGOFLAGS        string   // literal workflow environment before command-local overrides
	unknownEnvGOFLAGS bool     // the deciding workflow environment is not provably literal
	goFlagsProblem    string   // inherited GOFLAGS may have been changed outside the invocation
	goFlags           []string // timeout values from this command's effective GOFLAGS, in order
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

// makefileTimeoutParseError reports a recipe reader error only if the Makefile
// contains a test candidate after recipe line splices are removed.
func makefileTimeoutParseError(text string, err error) error {
	if !testInvocation.MatchString(strings.NewReplacer("\\\r\n\t", "", "\\\n\t", "").Replace(text)) {
		return nil
	}
	return fmt.Errorf("[FAIL] %s: %w", testTimeoutGate, err)
}

// makefileTimeouts checks recipes and immediate Make expansions, keeping independent findings.
func makefileTimeouts(text string) ([]string, error) {
	file, err := util.MakefileRecipes(text, maxTimeoutWorkflowLines)
	if err != nil {
		return nil, makefileTimeoutParseError(text, err)
	}
	oneShell := file.Targets[".ONESHELL"] || util.MakefileHasTarget(text, ".ONESHELL")
	source := makefileTimeoutSource(text)
	if file.MayExportGOFLAGS || file.Targets[".EXPORT_ALL_VARIABLES"] {
		source.goFlagsProblem = "cannot verify inherited GOFLAGS from Make exports"
	}
	var findings []string
	var failures []error
	source.collectMakefileCommandTimeouts(file.Recipes, oneShell, &findings, &failures)
	source.collectMakefileCommandTimeouts(file.ShellAssignments, false, &findings, &failures)
	for _, immediate := range file.Immediate {
		if err := source.immediateMakeTimeout(immediate); err != nil {
			failures = append(failures, err)
		}
	}
	return findings, errors.Join(failures...)
}

// collectMakefileCommandTimeouts appends findings and individual errors in source order.
// sharedShell applies only to recipes and does not replace an existing unresolved reason.
func (s timeoutSource) collectMakefileCommandTimeouts(commands []util.MakefileRecipe, sharedShell bool, findings *[]string, failures *[]error) {
	for _, command := range commands {
		if sharedShell && command.Unresolved == "" {
			command.Unresolved = ".ONESHELL recipes share a shell"
		}
		location := s
		if location.goFlagsProblem == "" {
			location.goFlagsProblem = command.GOFLAGSProblem
		}
		result, err := location.recipeTimeouts(command)
		if err != nil {
			*failures = append(*failures, err)
		}
		*findings = append(*findings, result...)
	}
}

// immediateMakeTimeout refuses candidate-bearing Make functions rather than treating
// their arguments as shell code. Commands executed by != are checked separately.
func (s timeoutSource) immediateMakeTimeout(source util.MakefileRecipe) error {
	first := len(source.Text)
	for start, end := range source.LiteralSpans {
		ref := source.Text[start:end]
		if len(ref) < 4 || (ref[1] != '(' && ref[1] != '{') {
			continue
		}
		body := ref[2 : len(ref)-1]
		space := strings.IndexAny(body, " \t\n")
		if space <= 0 {
			continue
		}
		args := body[space+1:]
		if at := rawTestCandidate(args); at != nil {
			first = min(first, start+2+space+1+at[0])
			continue
		}
		for _, at := range makeReferences.FindAllStringIndex(args, -1) {
			if _, known := s.wrapperName(args[at[0]:at[1]]); known {
				first = min(first, start+2+space+1+at[0])
				break
			}
		}
	}
	if first == len(source.Text) {
		return nil
	}
	s.line = func(n int) int { return source.Line + n + 1 }
	return s.refuse(source.Text, first, "evaluated Make function outside recipe")
}

// makefileTimeoutSource separates evidence that a variable can invoke tests from proof of
// its effective arguments. Visit each candidate once, including aliases of candidate variables.
func makefileTimeoutSource(text string) timeoutSource {
	wrappers := make(map[string]timeoutWrapper)
	var names []string
	mark := func(name string) {
		if _, found := wrappers[name]; !found {
			wrappers[name] = timeoutWrapper{}
			names = append(names, name)
		}
	}
	mark("GO_TEST")
	uses := make(map[string][]string)
	maxNames := 1
	assignments, defaultDirectory := util.MakefileSimpleAssignments(text, "CURDIR", func(name, value string) {
		maxNames++
		if rawTestCandidate(value) != nil {
			mark(name)
		}
		for _, reference := range makeReferences.FindAllString(value, -1) {
			key := reference[2 : len(reference)-1]
			uses[key] = append(uses[key], name)
		}
	})
	for i := 0; i < len(names) && i < maxNames; i++ {
		name := names[i]
		wrappers[name] = readTimeoutWrapper(assignments[name], defaultDirectory)
		for _, use := range uses[name] {
			mark(use)
		}
	}
	return timeoutSource{file: "Makefile", assignments: assignments, wrappers: wrappers}
}

// candidate also recognizes references to Make assignments whose values contain test commands.
// Literal spans keep shell dollars distinct from Make references. Choose the first byte in source order.
func (s timeoutSource) candidate(script string) []int {
	at := rawTestCandidate(script)
	for start, end := range s.literals {
		if _, known := s.wrapperName(script[start:end]); known && (at == nil || start < at[0]) {
			at = []int{start, end}
		}
	}
	return at
}

// wrapperName looks up one whole Make reference from the recipe reader's literal spans.
func (s timeoutSource) wrapperName(reference string) (string, bool) {
	if len(reference) < 4 || reference[0] != '$' {
		return "", false
	}
	name := reference[2 : len(reference)-1]
	_, found := s.wrappers[name]
	return name, found
}

// recipeTimeouts checks logical recipe lines holding a raw test command or a reference to one.
func (s timeoutSource) recipeTimeouts(recipe util.MakefileRecipe) ([]string, error) {
	script := recipe.Text
	s.literals = recipe.LiteralSpans
	candidate := s.candidate(script)
	if candidate == nil {
		return nil, nil
	}
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

var shellGOFLAGSName = regexp.MustCompile(`\b` + candidateWord("GOFLAGS") + `\b`)

// shellGOFLAGSOffset finds the first possible shell-side GOFLAGS change. The
// command reader can omit assignment-only statements, so retain unmatched text.
// Ignore comments and assignments already accounted for as test-local prefixes.
func (s timeoutSource) shellGOFLAGSOffset(script string, source hiss.ShellCommandSource, uncommented []byte) int {
	if !strings.Contains(string(uncommented), "GOFLAGS") && !shellGOFLAGSName.Match(uncommented) {
		return len(script)
	}
	text := append([]byte(nil), uncommented...)
	for _, command := range source.Commands {
		s.blankAccountedGOFLAGS(script, command, text)
	}
	if at := shellGOFLAGSName.FindIndex(text); at != nil {
		return at[0]
	}
	return len(script)
}

// blankAccountedGOFLAGS masks read-only operands, proven Actions env-file echo
// data, and literal test-local GOFLAGS prefixes without changing source offsets.
func (s timeoutSource) blankAccountedGOFLAGS(script string, command hiss.ShellCodeCommand, text []byte) {
	if s.workflowShell {
		blankTimeoutEnvEchoData(command, text)
	}
	if s.readOnlyGOFLAGSPrintf(script, command) {
		for _, word := range command.Words[1:] {
			blankTimeoutSpan(text, word.Span)
		}
	}
	args, reason := s.commandArgs(script, command)
	if args == nil || reason != "" {
		return
	}
	for _, word := range command.Prefix {
		if strings.HasPrefix(word.Code, "GOFLAGS=") && literalGoFlags.MatchString(strings.TrimPrefix(word.Text, "GOFLAGS=")) {
			blankTimeoutSpan(text, word.Span)
		}
	}
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
	var failures []error
	goFlagsOffset := s.shellGOFLAGSOffset(script, source, remaining)
	for _, command := range source.Commands {
		location := s
		start := command.Words[0].Span[0]
		if len(command.Prefix) != 0 {
			start = command.Prefix[0].Span[0]
		}
		if goFlagsOffset < start {
			location.goFlagsProblem = "cannot verify inherited GOFLAGS after prior shell text"
		}
		long, matched, reason := location.checkCommand(script, command, binding, defaults)
		if !matched && reason == "" {
			continue
		}
		if reason != "" {
			failures = append(failures, s.refuse(script, command.Words[0].Span[0], reason))
		}
		findings = append(findings, long...)
		blankTimeoutSpan(remaining, command.Words[0].Span)
	}
	raw := string(remaining)
	if at := s.candidate(raw); at != nil {
		failures = append(failures, s.refuse(script, at[0], unresolvedTestReason(raw, at)))
	}
	return findings, errors.Join(failures...)
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
	s.goFlags, reason = s.commandGOFLAGS(command.Prefix)
	if reason != "" {
		return nil, true, reason
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
	if name, known := s.wrapperName(program.Text); known && s.literals[program.Span[0]] == program.Span[1] {
		return s.wrappers[name].arguments(name, words[1:])
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
