// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cordanaLLM/praetor/internal/hiss"
)

// testFlagKind describes the argument positions owned by an audited flag.
type testFlagKind uint8

const (
	packageArg testFlagKind = iota
	switchFlag
	verboseFlag
	finalSwitchFlag
	valueFlag
	durationFlag
)

// timeoutTestFlags describes the flags in the engine's test commands. Go 1.27.4's
// cmd/go/internal/test/testflag.go and cmd/go/internal/work/build.go register the Go
// flags. cmd/go/internal/test/flagdefs.go lists the flags with a test.* spelling.
var timeoutTestFlags = map[string]struct {
	kind      testFlagKind
	forwarded bool
}{
	"count":                 {valueFlag, true},
	"covermode":             {valueFlag, false},
	"coverprofile":          {valueFlag, true},
	"exec":                  {valueFlag, false},
	"fuzz":                  {valueFlag, true},
	"fuzztime":              {valueFlag, true},
	"json":                  {switchFlag, false},
	"mod":                   {valueFlag, false},
	"p":                     {valueFlag, false},
	"race":                  {switchFlag, false},
	"run":                   {valueFlag, true},
	"short":                 {switchFlag, true},
	"skip":                  {valueFlag, true},
	"tags":                  {valueFlag, false},
	"timeout":               {durationFlag, true},
	"v":                     {verboseFlag, true},
	"vet":                   {valueFlag, false},
	"update-harness-golden": {finalSwitchFlag, false}, // internal/adopt/harness_golden_test.go
}

// testFlagRole looks up a single- or double-dash spelling, including registered test.* aliases.
func testFlagRole(name string) testFlagKind {
	name, flag := strings.CutPrefix(name, "-")
	if !flag {
		return packageArg
	}
	name, alias := strings.CutPrefix(strings.TrimPrefix(name, "-"), "test.")
	spec := timeoutTestFlags[name]
	if alias && !spec.forwarded {
		return packageArg
	}
	return spec.kind
}

const (
	packageSpelling = `[[:alnum:]_./][[:alnum:]_./+~-]*`
	parameterName   = `[a-zA-Z_][a-zA-Z_0-9]*`
	scalarParameter = `\$(?:` + parameterName + `|\{` + parameterName + `\})`
	unknownTestWord = "unexpanded argument in test invocation"
)

var (
	// Only a successful, initial literal assignment followed directly by this invocation
	// establishes an unguarded parameter's value without interpreting intervening shell code.
	initialPackageBinding = regexp.MustCompile(`^[ \t\n]*(` + parameterName + `)=` + packageSpelling + `[ \t]+&&[ \t\n]+`)
	literalPackage        = regexp.MustCompile(`^` + packageSpelling + `$`)
	// A quoted scalar remains one value. An array in a flag's value slot can add flags.
	scalarFlagValue = regexp.MustCompile(`^(?:--?(?:test\.)?[a-z]+=)?"` + scalarParameter + `(?:/[a-zA-Z0-9._/-]+)?"$`)
	// Literal path prefixes and longest-prefix removal both exclude a leading dash,
	// even when the caller supplies a flag instead of a package.
	quotedPackage   = regexp.MustCompile(`^"(?:\./` + scalarParameter + `|\$\{` + parameterName + `(?:\[@\])?##-\*\})"$`)
	literalTestWord = regexp.MustCompile(`^(?:[a-zA-Z0-9_.,/:@+=~^-]|'[^']*'|"[^"$` + "`" + `\\]*"|\\[^\n])+\$?$`)
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
func (w timeoutWrapper) arguments(name string, use []hiss.ShellCodeWord) ([]hiss.ShellCodeWord, string) {
	if w.args == nil {
		return nil, name + " needs one literal test command in a root Makefile assignment"
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
	if testFlagRole(name) != durationFlag {
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
	name, value, attached := strings.Cut(word.Value, "=")
	arg := testArg{kind: testFlagRole(name), end: i}
	switch arg.kind {
	case switchFlag, verboseFlag, finalSwitchFlag:
		if arg.kind.acceptsSwitch(value, attached, args, i) {
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

// acceptsSwitch follows Go's attached boolean syntax. Only the documented adopter
// invocation can end with its package-specific golden regeneration switch.
func (kind testFlagKind) acceptsSwitch(value string, attached bool, args []hiss.ShellCodeWord, i int) bool {
	if kind == finalSwitchFlag && (i+1 != len(args) || args[0].Value != "./internal/adopt") {
		return false
	}
	if !attached || kind == verboseFlag && value == "test2json" {
		return true
	}
	_, err := strconv.ParseBool(value)
	return err == nil
}

var (
	localAssignment = regexp.MustCompile(`^` + parameterName + `=`)
	// An assignment RHS is not subject to field splitting or globbing. Admit
	// literal fragments, but not shell expansions or unquoted tilde expansion.
	literalGoFlags = regexp.MustCompile(`^(?:[a-zA-Z0-9_.,/:@+=^-]|'[^']*'|"(?:[^"$` + "`" + `\\]|\\["\\$` + "`" + `])*"|\\[^\n])*$`)
)

// allowsCommandGOFLAGS reports whether a prefix word is an assignment or an accepted wrapper.
func allowsCommandGOFLAGS(word hiss.ShellCodeWord) bool {
	return localAssignment.MatchString(word.Code) || word.Text == "env" || word.Text == "exec" || word.Text == "command"
}

// literalCommandGOFLAGS reports whether a command-local GOFLAGS assignment has a literal value.
func (s timeoutSource) literalCommandGOFLAGS(assignment hiss.ShellCodeWord) bool {
	raw := strings.TrimPrefix(assignment.Text, "GOFLAGS=")
	return !strings.Contains(raw, "${{") && !s.hasMakeReference(assignment) && literalGoFlags.MatchString(raw)
}

// commandGOFLAGS reads the last command-local assignment, falling back to the
// workflow environment only if there is no local assignment. A wrapper that may
// change the environment cannot be assumed to pass GOFLAGS through.
func (s timeoutSource) commandGOFLAGS(prefix []hiss.ShellCodeWord) ([]string, string) {
	var assignment *hiss.ShellCodeWord
	for i := range prefix {
		if strings.HasPrefix(prefix[i].Code, "GOFLAGS=") {
			assignment = &prefix[i]
		}
	}
	flags, origin := s.envGOFLAGS, "inherited"
	if assignment != nil {
		origin = "command-local"
		if !s.literalCommandGOFLAGS(*assignment) {
			return nil, "cannot verify dynamic command-local GOFLAGS assignment"
		}
		flags = strings.TrimPrefix(assignment.Value, "GOFLAGS=")
	} else if s.goFlagsProblem != "" {
		return nil, s.goFlagsProblem
	} else if s.unknownEnvGOFLAGS {
		return nil, "cannot verify inherited GOFLAGS from workflow environment"
	} else if flags == "" {
		return nil, ""
	}
	for _, word := range prefix {
		if !allowsCommandGOFLAGS(word) {
			return nil, "cannot verify " + origin + " GOFLAGS through shell wrapper"
		}
	}
	return goFlagsTimeouts(flags)
}

const goFlagsBlanks = " \t\r\n"

// readGOFLAGSField reads one field from nonempty text with no leading blanks.
// Only a quote at the start of a field quotes it; quotes and backslashes
// inside an unquoted field are data.
func readGOFLAGSField(text string) (field, rest, problem string) {
	if text[0] == '\'' || text[0] == '"' {
		end := strings.IndexByte(text[1:], text[0])
		if end < 0 {
			return "", "", "unterminated quote in GOFLAGS"
		}
		return text[1 : end+1], text[end+2:], ""
	}
	if end := strings.IndexAny(text, goFlagsBlanks); end >= 0 {
		return text[:end], text[end:], ""
	}
	return text, "", ""
}

// goFlagsTimeouts follows cmd/go's GOFLAGS framing: each field is a complete
// flag, with a value attached by '='.
func goFlagsTimeouts(text string) ([]string, string) {
	var durations []string
	for text = strings.TrimLeft(text, goFlagsBlanks); text != ""; text = strings.TrimLeft(text, goFlagsBlanks) {
		field, rest, problem := readGOFLAGSField(text)
		if problem != "" {
			return nil, problem
		}
		text = rest
		name, value, attached := strings.Cut(field, "=")
		if !strings.HasPrefix(name, "-") || name == "-" || name == "--" {
			return nil, "GOFLAGS entries must be standalone flags"
		}
		if testFlagRole(name) != durationFlag {
			continue
		}
		if !attached || value == "" {
			return nil, "GOFLAGS timeout requires an attached duration"
		}
		if len(durations) == maxTimeoutFlagsPerCommand {
			return nil, "timeout flag count exceeds the reader bound"
		}
		durations = append(durations, value)
	}
	return durations, ""
}

// timeoutArguments records a single contiguous package list and the durations in Go flag order.
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

// explicitTimeouts checks all timeout values, but applies the duration policy
// only to the last setting. Go reads GOFLAGS before the command-line flags.
func (s timeoutSource) explicitTimeouts(where string, args []hiss.ShellCodeWord, defaults map[string]exprValue) ([]string, string) {
	parsed := timeoutArguments{durations: s.goFlags[:len(s.goFlags):len(s.goFlags)]}
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
	var effectiveFinding string
	for i, value := range parsed.durations {
		if i < len(parsed.durations)-1 {
			if _, _, reason := parseTimeoutDuration(value, defaults); reason != "" {
				return nil, reason
			}
			continue
		}
		finding, reason := judgeTimeout(where, value, defaults)
		if reason != "" {
			return nil, reason
		}
		effectiveFinding = finding
	}
	if effectiveFinding != "" {
		return []string{effectiveFinding}, ""
	}
	return nil, ""
}
