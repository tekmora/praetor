// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"regexp"
	"strings"

	"github.com/cordanaLLM/praetor/internal/hiss"
)

// testFlagKind describes the argument positions owned by an audited flag.
type testFlagKind uint8

const (
	packageArg testFlagKind = iota
	directoryFlag
	switchFlag
	valueFlag
	durationFlag
)

// timeoutTestFlags is the complete flag grammar. Go 1.27.4 registers test.timeout
// alongside timeout in cmd/go/internal/test, and cmdflag.ParseOne accepts either dash count.
var timeoutTestFlags = map[string]testFlagKind{
	"-C":             directoryFlag,
	"-json":          switchFlag,
	"-race":          switchFlag,
	"-v":             switchFlag,
	"-count":         valueFlag,
	"-covermode":     valueFlag,
	"-coverprofile":  valueFlag,
	"-fuzz":          valueFlag,
	"-fuzztime":      valueFlag,
	"-run":           valueFlag,
	"-skip":          valueFlag,
	"-timeout":       durationFlag,
	"--timeout":      durationFlag,
	"-test.timeout":  durationFlag,
	"--test.timeout": durationFlag,
}

const (
	packageSpelling = `[[:alnum:]_./][[:alnum:]_./+~-]*`
	parameterName   = `[a-zA-Z_][a-zA-Z_0-9]*`
	scalarParameter = `\$(?:` + parameterName + `|\{` + parameterName + `\})`
	unknownTestWord = "unexpanded argument in test invocation"
	badTestWrapper  = "GO_TEST needs one literal test command in a root Makefile assignment"
)

var (
	// Only a successful, initial literal assignment followed directly by this invocation
	// establishes an unguarded parameter's value without interpreting intervening shell code.
	initialPackageBinding = regexp.MustCompile(`^[ \t\n]*(` + parameterName + `)=` + packageSpelling + `[ \t]+&&[ \t\n]+`)
	literalPackage        = regexp.MustCompile(`^` + packageSpelling + `$`)
	// A quoted scalar remains one value. An array in a flag's value slot can add flags.
	scalarFlagValue = regexp.MustCompile(`^(?:-[a-z]+=)?"` + scalarParameter + `(?:/[a-zA-Z0-9._/-]+)?"$`)
	// Literal path prefixes and longest-prefix removal both exclude a leading dash,
	// even when the caller supplies a flag instead of a package.
	quotedPackage   = regexp.MustCompile(`^"(?:\./` + scalarParameter + `|\$\{` + parameterName + `(?:\[@\])?##-\*\})"$`)
	literalTestWord = regexp.MustCompile(`^(?:[a-zA-Z0-9_.,/:@+=~-]|'[^']*'|"[^"$` + "`" + `\\]*"|\\[^\n])+$`)
	literalMakeWord = regexp.MustCompile(`^[a-zA-Z0-9_.,/:@+=~-]+$`)
	// go list emits one import path per package. The optional Make error branch
	// contributes no words when discovery succeeds.
	listedPackages = regexp.MustCompile(`^\$\(shell go list ` + packageSpelling +
		`\)(?:\$\(if \$\(filter-out 0,\$\(\.SHELLSTATUS\)\),\$\(error [a-zA-Z0-9 ._-]+\)\))?$`)
)

// timeoutWrapper holds the fixed argument prefix and the standardsctl directory convention.
type timeoutWrapper struct {
	args      []hiss.ShellCodeWord
	sandboxed bool
}

// readTimeoutWrapper reads the definition once. Make references are only supported in the
// fixed standardsctl program path. Comments and shell operators require expansion or execution.
func readTimeoutWrapper(definition string, defaultDirectory bool) timeoutWrapper {
	const sandbox = `go run "$(CURDIR)/cmd/standardsctl" `
	head, sandboxed := strings.CutPrefix(definition, sandbox)
	if head == "" || strings.ContainsAny(head, "$#\n") {
		return timeoutWrapper{}
	}
	words := literalWrapperCommand(head)
	if len(words) < 2 {
		return timeoutWrapper{}
	}
	if sandboxed && (!defaultDirectory || words[0].Text != "go" || words[1].Text != "test") {
		return timeoutWrapper{}
	}
	return timeoutWrapper{args: goTestArgs(words), sandboxed: sandboxed}
}

// literalWrapperCommand accepts a single shell command covering the entire definition.
func literalWrapperCommand(head string) []hiss.ShellCodeWord {
	commands, ok := hiss.ShellCodeCommands(head, 1, nil)
	if !ok || len(commands) != 1 {
		return nil
	}
	words := commands[0].Words
	if words[0].Span[0] != 0 || words[len(words)-1].Span[1] != len(head) {
		return nil
	}
	for _, word := range words {
		if !literalTestWord.MatchString(word.Text) {
			return nil
		}
	}
	return words
}

// arguments joins definition and use before assigning flag values, without modifying the prefix.
func (w timeoutWrapper) arguments(use []hiss.ShellCodeWord) ([]hiss.ShellCodeWord, string) {
	if w.args == nil {
		return nil, badTestWrapper
	}
	args := append(w.args[:len(w.args):len(w.args)], use...)
	if w.sandboxed {
		args = skipGoDirectory(args)
	}
	return args, ""
}

// flagArgument consumes one attached or separate argument, preserving the shell word for validation.
func flagArgument(args []hiss.ShellCodeWord, i int) (string, int) {
	if _, value, attached := strings.Cut(args[i].Value, "="); attached {
		return value, i
	}
	if i+1 < len(args) {
		return args[i+1].Value, i + 1
	}
	return "", i
}

// timeoutValue reads a timeout spelling and its attached or separate duration.
func timeoutValue(args []hiss.ShellCodeWord, i int) (string, int, bool) {
	name, _, _ := strings.Cut(args[i].Value, "=")
	if timeoutTestFlags[name] != durationFlag {
		return "", i, false
	}
	value, next := flagArgument(args, i)
	return value, next, true
}

// makeArgument returns a whole Make reference's checked assignment, including an empty value.
func (s timeoutSource) makeArgument(word hiss.ShellCodeWord) (string, bool) {
	if s.literals[word.Span[0]] != word.Span[1] || !makeVariable.MatchString(word.Text) {
		return "", false
	}
	value, ok := s.assignments[word.Text[2:len(word.Text)-1]]
	return value, ok
}

// packageOperand requires path text or an expansion whose contents cannot introduce a flag.
func (s timeoutSource) packageOperand(word hiss.ShellCodeWord) bool {
	if value, ok := s.makeArgument(word); ok {
		return literalPackage.MatchString(value) || listedPackages.MatchString(value)
	}
	if literalPackage.MatchString(word.Value) {
		return literalTestWord.MatchString(word.Text)
	}
	if s.hasMakeReference(word) {
		return false
	}
	if s.packageName != "" && (word.Text == `"$`+s.packageName+`"` || word.Text == `"${`+s.packageName+`}"`) {
		return true
	}
	return quotedPackage.MatchString(word.Text)
}

// hasMakeReference distinguishes shell parameters from text expanded by Make before the shell.
// Only words with a dollar can contain one of the reader's Make references.
func (s timeoutSource) hasMakeReference(word hiss.ShellCodeWord) bool {
	if !strings.Contains(word.Text, "$") {
		return false
	}
	for i := word.Span[0]; i < word.Span[1]; i++ {
		if s.literals[i] != 0 {
			return true
		}
	}
	return false
}

// flagValue allows literal words and single quoted scalar expansions in a known value slot.
func (s timeoutSource) flagValue(word hiss.ShellCodeWord) bool {
	if value, ok := s.makeArgument(word); ok {
		return literalMakeWord.MatchString(value)
	}
	if strings.Contains(word.Text, "${{") || s.hasMakeReference(word) {
		return false
	}
	return literalTestWord.MatchString(word.Text) || scalarFlagValue.MatchString(word.Text)
}

// testArg holds one grammar token and the index of the last word it consumes.
// A package argument consumes one word.
type testArg struct {
	kind  testFlagKind
	end   int
	value string
}

// testArgument assigns each word a role, consuming the next word only for a flag that owns it.
func (s timeoutSource) testArgument(args []hiss.ShellCodeWord, i int) (testArg, string) {
	if value, next, found := timeoutValue(args, i); found {
		return testArg{kind: durationFlag, end: next, value: value}, ""
	}
	word := args[i]
	name, _, attached := strings.Cut(word.Value, "=")
	arg := testArg{kind: timeoutTestFlags[name], end: i}
	switch arg.kind {
	case switchFlag:
		if !attached {
			return arg, ""
		}
	case valueFlag:
		arg.value, arg.end = flagArgument(args, i)
		if (attached || arg.end > i) && s.flagValue(args[arg.end]) {
			return arg, ""
		}
	case packageArg:
		if s.packageOperand(word) {
			return arg, ""
		}
	}
	return arg, unknownTestWord
}

// timeoutArguments records a single contiguous package list and all explicit durations.
type timeoutArguments struct {
	packages, afterPackages bool
	durations               []string
}

// accept enforces package position and the reader's scalar timeout bound across both argument sources.
func (a *timeoutArguments) accept(arg testArg) string {
	if arg.kind == packageArg {
		if a.afterPackages {
			return "package operand after the package list ended"
		}
		a.packages = true
		return ""
	}
	a.afterPackages = a.packages
	if arg.kind == durationFlag {
		if len(a.durations) == maxTimeoutFlagsPerCommand {
			return "timeout flag count exceeds the reader bound"
		}
		if arg.value == "" {
			return "missing timeout value"
		}
		a.durations = append(a.durations, arg.value)
	}
	return ""
}

// explicitTimeouts checks every word and judges every duration across the definition and use.
func (s timeoutSource) explicitTimeouts(where string, args []hiss.ShellCodeWord, defaults map[string]exprValue) ([]string, string) {
	var parsed timeoutArguments
	for i := 0; i < len(args); i++ {
		arg, reason := s.testArgument(args, i)
		if reason != "" {
			return nil, reason
		}
		if reason := parsed.accept(arg); reason != "" {
			return nil, reason
		}
		i = arg.end
	}
	var findings []string
	for _, value := range parsed.durations {
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
