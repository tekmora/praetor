package util

import (
	"bytes"
	"iter"
	"slices"
	"strings"
)

// This file, makefile_define.go, makefile_scanner.go and makefile_variables.go hold the one
// Makefile reader Praetor decides target ownership with. Adoption asks it whether a project owns
// verify-all or docs-lint before appending a rule (internal/adopt/governance.go,
// internal/adopt/verification_makefile.go), and editor generation asks it whether to offer a
// "make verify-all" task (internal/editor/capabilities.go). A second line test beside it once read
// eight assignment forms as rules (issue #304), so a caller never decides rule versus assignment
// on its own.
//
// The reader works on logical lines, as Make does: a line ending in an odd run of backslashes
// continues on the next one (makefileLogicalLines). It reads a Makefile up to the first point it
// cannot resolve -- line MaxMakefileLines + 1, a logical line longer than MaxMakefileLineBytes, a
// chain of more than MaxMakefileContinuations continuations, or a line whose meaning depends on a
// conditional branch or on a computed name (makefileScanner). A rule before that point counts for
// MakefileHasTarget, nothing at or after it does, and MakefileMayDefineTarget reports the file as
// one only Make can resolve.

// MaxMakefileLines bounds how many physical lines of a Makefile the reader scans (HISS-02). A
// rule past the bound is not read: MakefileHasTarget reports none, and MakefileMayDefineTarget
// reports the longer file as one only Make can resolve.
const MaxMakefileLines = 4096

// MaxMakefileContinuations bounds how many continuation lines the reader joins to one logical
// line (HISS-02): 256 continuations make a logical line of 257 physical lines. A longer chain is
// a point the reader cannot resolve, so the reading stops there.
const MaxMakefileContinuations = 256

// A Makefile line is read token by token; these name what a token turned out to be.
const (
	makefileAssignToken    = "assign"
	makefileRuleToken      = "rule"
	makefileEndToken       = "end"
	makefileReferenceToken = "reference"
)

// MaxMakefileLineBytes bounds the token scan of a single logical Makefile line (HISS-02), joined
// continuations included. Real declarations are far shorter; a longer line is a point the reader
// cannot resolve, so the reading stops there and a caller preserves the file instead of appending
// to it.
const MaxMakefileLineBytes = 8192

// makefileReferenceWidth returns the byte length of the variable reference text opens with, so the
// colon and the "=" inside "$(SRCS:.c=.o)" or "$(call rule,$(P)x,A=b)" are not read as operators.
// "$x" and "$$" span two bytes. Like GNU Make 4.4.1 it counts nested brackets of the kind the
// reference opens with: "$(a $(b),c=d)" ends at its last ")", a "}" inside "$(" is plain text, and
// a reference that is never closed spans the rest of text.
func makefileReferenceWidth(text string) int {
	if len(text) < 2 {
		return 1
	}
	closer := makefileCloser(text[1])
	if closer == 0 {
		return 2
	}
	depth := 0
	for end := 1; end < len(text) && end < MaxMakefileLineBytes; end++ {
		switch text[end] {
		case text[1]:
			depth++
		case closer:
			depth--
		}
		if depth == 0 {
			return end + 1
		}
	}
	return len(text)
}

// makefileCloser returns the bracket that closes a variable reference opened with open, "(" or
// "{", and 0 for any other byte.
func makefileCloser(open byte) byte {
	switch open {
	case '(':
		return ')'
	case '{':
		return '}'
	}
	return 0
}

// makefileReference classifies the "$" text opens with: "$$" is an escaped dollar sign that
// expands to a literal "$", anything else a variable reference Make expands.
func makefileReference(text string) (string, int) {
	if strings.HasPrefix(text, "$$") {
		return "", 2
	}
	return makefileReferenceToken, makefileReferenceWidth(text)
}

// makefileColonOperator classifies the run of colons starting at line[i]. A run followed by "=" is
// an assignment operator (":=", "::=", ":::="); any other run separates targets from prerequisites.
func makefileColonOperator(line string, i int) (string, int) {
	run := i
	for run < len(line) && run < MaxMakefileLineBytes && line[run] == ':' {
		run++
	}
	if run < len(line) && line[run] == '=' {
		return makefileAssignToken, run - i + 1
	}
	return makefileRuleToken, run - i
}

// makefileOperatorAt classifies the token starting at line[i] and reports the bytes it spans. Make
// ends a variable name at "=", "+=", "?=", "!=" or a run of colons followed by "="; it stops
// reading the line at an unescaped "#" (a comment) or ";" (the inline recipe), and a backslash
// escapes the byte behind it (makefileEscapeWidth).
func makefileOperatorAt(line string, i int) (string, int) {
	switch line[i] {
	case '=':
		return makefileAssignToken, 1
	case '+', '?', '!':
		if i+1 < len(line) && line[i+1] == '=' {
			return makefileAssignToken, 2
		}
	case ':':
		return makefileColonOperator(line, i)
	case '$':
		return makefileReference(line[i:])
	case '#', ';':
		return makefileEndToken, 1
	case '\\':
		return "", makefileEscapeWidth(line, i)
	}
	return "", 1
}

// makefileEscapeWidth returns the bytes the backslash at line[i] spans: two when it escapes the
// byte behind it, so "\#" and "\:" are no operators, and one before "$" or a blank, which it
// leaves as they are. Make has no backslash escape for a reference, so measured against GNU Make
// 4.4.1 "\$(R)" with "R = x docs-lint: ; @echo x" declares docs-lint; and a blank still ends a
// word, so "foo\ bar = docs-lint: ; @echo x" is a rule with two words in front of "="
// (makefileAssignment).
func makefileEscapeWidth(line string, i int) int {
	if i+1 < len(line) && !strings.ContainsRune("$ \t", rune(line[i+1])) {
		return 2
	}
	return 1
}

// makefileSplit returns the byte offsets of the first variable-assignment operator, of the first
// rule colon and of the first variable reference on line, each -1 when the line holds none. Make
// reads whichever operator comes first: an assignment first binds a variable whose value may
// itself contain colons ("V = a:b"), a colon first opens a rule ("t: dep"). The scan ends where
// Make stops reading the line -- at a comment or at the ";" that opens an inline recipe -- and at
// MaxMakefileLineBytes (HISS-02).
func makefileSplit(line string) (assign, colon, reference int) {
	assign, colon, reference = -1, -1, -1
	for i := 0; i < len(line) && i < MaxMakefileLineBytes; {
		kind, width := makefileOperatorAt(line, i)
		switch {
		case kind == makefileEndToken:
			return assign, colon, reference
		case kind == makefileAssignToken && assign < 0:
			assign = i
		case kind == makefileRuleToken && colon < 0:
			colon = i
		case kind == makefileReferenceToken && reference < 0:
			reference = i
		}
		i += width
	}
	return assign, colon, reference
}

// makefileBindsVariable reports whether text binds a variable rather than opening a rule, decided
// by whichever operator Make reaches first and by the name in front of it (makefileAssignment).
func makefileBindsVariable(text string) bool {
	binds, _ := makefileAssignment(text)
	return binds
}

// makefileLeadingAssignment returns the assignment operator offset when it precedes any rule delimiter.
func makefileLeadingAssignment(line string) int {
	assign, colon, _ := makefileSplit(line)
	if colon >= 0 && colon < assign {
		return -1
	}
	return assign
}

// makefileAssignment reports whether Make reaches an assignment operator in text before any rule
// colon, and if so whether it binds a variable (binds) or not, because its name side holds two or
// more words after the modifiers (unnamed). GNU Make takes no blank inside a variable name, so
// measured against GNU Make 4.4.1 "foo bar = docs-lint: ; @echo x" and "override foo bar = ..." are
// rules declaring docs-lint, "$(R) x = y" is a bare expansion, and "export foo bar = ..." stays an
// export directive.
func makefileAssignment(text string) (binds, unnamed bool) {
	assign := makefileLeadingAssignment(text)
	if assign < 0 {
		return false, false
	}
	named := len(makefileNameWords(text[:assign])) <= 1
	return named, !named
}

// makefileNameWords returns the blank-separated words of text, the name side of an assignment,
// after the override, export, unexport and private modifiers in front of it. A variable reference
// belongs to the word it sits in, so "$(a b)x" is one word.
func makefileNameWords(text string) []string {
	words := make([]string, 0, 4)
	start := -1
	for i := 0; i < len(text) && i < MaxMakefileLineBytes; {
		if text[i] == ' ' || text[i] == '\t' {
			if start >= 0 {
				words = append(words, text[start:i])
			}
			start = -1
			i++
			continue
		}
		if start < 0 {
			start = i
		}
		_, width := makefileOperatorAt(text, i)
		i += width
	}
	if start >= 0 {
		words = append(words, text[start:])
	}
	return words[makefileDirectiveIndex(words):]
}

// makefileBoundName returns the name of the variable a trimmed line binds, by an assignment or by
// a define, and whether it binds one.
func makefileBoundName(line string) (string, bool) {
	fields := strings.Fields(line)
	if makefileOpensDefine(fields) {
		index := makefileDirectiveIndex(fields) + 1
		if index < len(fields) {
			return fields[index], true
		}
		return "", false
	}
	assign, _, _ := makefileSplit(line)
	if !makefileBindsVariable(line) {
		return "", false
	}
	words := makefileNameWords(line[:assign])
	if len(words) != 1 {
		return "", false
	}
	return words[0], true
}

// makefileNameMayBe reports whether name, a variable or function name that may hold references,
// can expand to want (makefileName.mayBe). So "$(P)PREFIX" may be .RECIPEPREFIX and "e$(S)" may
// be eval, while "$(PKG)_SRCS" can be neither.
func makefileNameMayBe(name, want string) bool {
	return makefileSplitName(name).mayBe(want)
}

// makefileName is a variable or function name split once into the literal runs around its
// references (makefileLiteralRuns), so a caller that tests one name against many can split it
// once: text is the name, and computed reports whether it holds a reference.
type makefileName struct {
	text     string
	runs     []string
	computed bool
}

// makefileSplitName returns name split into the literal runs around its references.
func makefileSplitName(name string) makefileName {
	runs, computed := makefileLiteralRuns(name)
	return makefileName{text: name, runs: runs, computed: computed}
}

// mayBe reports whether the name can expand to want: it equals want, or it holds a reference and
// every literal run around its references occurs in want.
func (n makefileName) mayBe(want string) bool {
	if !n.computed {
		return n.text == want
	}
	for _, run := range n.runs {
		if !strings.Contains(want, run) {
			return false
		}
	}
	return true
}

// makefileLiteralRuns splits name at its variable references into the literal text around them,
// and reports whether it holds a reference. An escaped "$$" is a literal "$".
func makefileLiteralRuns(name string) ([]string, bool) {
	runs := make([]string, 0, 4)
	var run strings.Builder
	computed := false
	for i := 0; i < len(name) && i < MaxMakefileLineBytes; {
		if name[i] != '$' {
			run.WriteByte(name[i])
			i++
			continue
		}
		kind, width := makefileReference(name[i:])
		if kind == makefileReferenceToken {
			runs, computed = append(runs, run.String()), true
			run.Reset()
		} else {
			run.WriteByte('$')
		}
		i += width
	}
	return append(runs, run.String()), computed
}

// makefileExportDirective reports whether line is an export or unexport directive: its first word,
// followed by whitespace, is "export" or "unexport". Make reads such a line as a list of variables
// to export and never as a rule, colon or not. Measured against GNU Make 4.4.1: "export
// verify-all: dep", "unexport verify-all: dep" and "export : dep" declare no target, while
// "export: dep" declares the target "export" and "override verify-all: dep", "private verify-all:
// dep" and "override export verify-all: dep" declare verify-all -- only the first word decides.
func makefileExportDirective(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	end := strings.IndexAny(trimmed, " \t")
	if end < 0 {
		return false
	}
	word := trimmed[:end]
	return word == "export" || word == "unexport"
}

// MakefileRuleParts returns the raw target head and tail on either side of the rule delimiter.
// It skips escaped colons and variable references and consumes both colons in a double-colon rule.
// Recipes, assignments (including target-specific bindings) and overlong lines are not rules here.
func MakefileRuleParts(line string) (head, tail string, ok bool) {
	if len(line) > MaxMakefileLineBytes || strings.HasPrefix(line, "\t") || makefileExportDirective(line) {
		return "", "", false
	}
	_, colon, _ := makefileSplit(line)
	if colon < 0 || makefileBindsVariable(line) {
		return "", "", false
	}
	_, width := makefileOperatorAt(line, colon)
	tail = line[colon+width:]
	if makefileBindsVariable(tail) {
		return "", "", false
	}
	return line[:colon], tail, true
}

// MakefileTargetWords splits a literal rule head at unquoted horizontal blanks.
// A head that needs expansion or exceeds MaxMakefileLineBytes returns nil.
func MakefileTargetWords(head string) []string {
	if len(head) > MaxMakefileLineBytes || strings.Contains(head, "$") {
		return nil
	}
	words := []string{}
	for head = strings.TrimLeft(head, " \t"); len(head) > 0; head = strings.TrimLeft(head, " \t") {
		var word strings.Builder
		for len(head) > 0 && head[0] != ' ' && head[0] != '\t' {
			part, width := makefileTargetPart(head)
			word.WriteString(part)
			head = head[width:]
		}
		words = append(words, word.String())
	}
	return words
}

// makefileTargetPart consumes a literal byte or a run of backslashes. GNU Make 4.4.1 src/read.c
// (parse_file_seq and find_map_unquote) keeps one backslash per pair before a blank. An odd
// last backslash includes the blank in the current filename.
func makefileTargetPart(text string) (part string, width int) {
	if text[0] != '\\' {
		return text[:1], 1
	}
	run := len(text) - len(strings.TrimLeft(text, `\`))
	if run == len(text) || (text[run] != ' ' && text[run] != '\t') {
		return text[:run], run
	}
	if run%2 == 1 {
		return text[:run/2] + text[run:run+1], run + 1
	}
	return text[:run/2], run
}

// makefileTrackedLine records one logical line together with the file and 1-indexed line number
// where it appeared, and whether it uses a continuation.
type makefileTrackedLine struct {
	text      string
	file      string
	line      int
	continued bool
}

// makefileTrackedLogicalLines returns the logical lines of data with each line's file and 1-based
// start line recorded, and false when the file exceeds the line bound.
func makefileTrackedLogicalLines(data, file string) ([]makefileTrackedLine, bool) {
	physical := strings.Split(data, "\n")
	lines := make([]makefileTrackedLine, 0, min(len(physical), MaxMakefileLines))
	for start := 0; start < len(physical) && start < MaxMakefileLines; {
		line, next, whole := makefileJoin(physical, start)
		if !whole {
			return lines, false
		}
		lines = append(lines, makefileTrackedLine{
			text:      strings.TrimSuffix(line, "\r"),
			file:      file,
			line:      start + 1,
			continued: next > start+1 || makefileContinues(physical[start]),
		})
		start = next
	}
	return lines, len(physical) <= MaxMakefileLines
}

// makefileLogicalLines returns the logical lines of data up to the first point the reader cannot
// resolve, and whether it read the whole file. Measured against GNU Make 4.4.1, a continuation
// joins every kind of line: an assignment ("HELP = usage \" then "  verify-all: x" binds HELP), a
// recipe line ("\techo a \" then "verify-all: x" is recipe text), a comment, a define body line
// (a continued line swallows the "endef" after it) and a rule line ("verify-all \" then
// "  other: dep" declares both targets).
func makefileLogicalLines(data string) ([]string, bool) {
	tracked, whole := makefileTrackedLogicalLines(data, "")
	lines := make([]string, len(tracked))
	for i, tl := range tracked {
		lines[i] = tl.text
	}
	return lines, whole
}

// makefileJoin returns the logical line that starts at physical[start], the index of the physical
// line after it, and whether the reader resolves it: false when its continuation chain is longer
// than MaxMakefileContinuations, when it ends past line MaxMakefileLines, or when the joined line
// is longer than MaxMakefileLineBytes. A backslash on the file's last line continues nothing.
func makefileJoin(physical []string, start int) (string, int, bool) {
	end := start
	for end-start < MaxMakefileContinuations && end+1 < len(physical) && makefileContinues(physical[end]) {
		end++
	}
	if end >= MaxMakefileLines || (end+1 < len(physical) && makefileContinues(physical[end])) {
		return "", end + 1, false
	}
	line := makefileJoinText(physical[start : end+1])
	return line, end + 1, len(line) <= MaxMakefileLineBytes
}

// makefileJoinText joins the physical lines of one logical line. A recipe line keeps them as they
// are, joined by "\n", so MakefileTargetRecipe returns the lines the file holds. Any other line
// joins as Make reads it: each backslash-newline and the blanks around it become one space, a run
// of them included and even when no text follows, and the blanks that end the last line stay.
// Measured against GNU Make 4.4.1, "X := docs-lint \" or "X := docs-lint\" followed by an empty
// line binds "docs-lint " with its blank, so "$(X)foo:" declares docs-lint and foo: the blanks
// decide the target names wherever a value is glued to text (makefileVariables).
func makefileJoinText(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	if strings.HasPrefix(parts[0], "\t") {
		return strings.Join(parts, "\n")
	}
	joined := make([]byte, 0, len(parts[0]))
	for index, part := range parts {
		part = strings.TrimSuffix(part, "\r")
		if makefileContinues(part) {
			part = part[:len(part)-1]
		}
		if index > 0 && len(joined) > 0 {
			joined = append(bytes.TrimRight(joined, " \t"), ' ')
		}
		joined = append(joined, strings.TrimLeft(part, " \t")...)
	}
	return string(joined)
}

// MakefileHasTarget reports whether data, the text of a Makefile, declares a rule for target on a
// line this reader resolves without Make: MakefileRuleParts distinguishes rules from assignments, a
// define body is variable text, not rules, so a "target:" line inside one declares nothing, a
// computed name counts once the file fixes its value ("$(GATE):" after "GATE := verify-all",
// makefileVariables). An unresolved head declares no known targets. A Makefile that names
// .RECIPEPREFIX declares nothing the reader can claim either (makefileNamesRecipePrefix).
// MakefileMayDefineTarget reports the files where Make may still declare the target some other
// way. Lines may end in "\n" or "\r\n"; the reading stops where makefileLogicalLines does.
func MakefileHasTarget(data, target string) bool {
	_, found := makefileFindRule(MakefileRules(data), target)
	return found
}

// makefileNamesRecipePrefix reports whether line, unless it is a comment line, names .RECIPEPREFIX.
// Assigning it changes which lines are recipe lines: measured against GNU Make 4.4.1, after
// ".RECIPEPREFIX = >" a tab-indented "docs-lint: ; @echo x" declares docs-lint and "> docs-lint:
// dep" is a recipe line. The reader tells recipe lines by the tab alone, so a Makefile that names
// the variable anywhere, in an assignment, an eval or a define body, is one only Make can read. A
// binding whose computed name may be .RECIPEPREFIX is a point the reader cannot resolve
// (makefileMayBindRecipePrefix).
func makefileNamesRecipePrefix(line string) bool {
	return strings.Contains(line, ".RECIPEPREFIX") && !strings.HasPrefix(strings.TrimSpace(line), "#")
}

// makefileMayBindRecipePrefix reports whether line, read as makefile syntax, binds a variable whose
// name may be .RECIPEPREFIX (makefileBoundName, makefileNameMayBe). Measured against GNU Make
// 4.4.1, "P = .RECIPE" and "$(P)PREFIX := >", or "N = .RECIPEPREFIX" and "$(N) := >", make a
// tab-indented "docs-lint: ; @echo x" after "all:" declare docs-lint. "$(PKG)_SRCS := a.c" can
// name no such variable.
func makefileMayBindRecipePrefix(line string) bool {
	name, binds := makefileBoundName(strings.TrimSpace(line))
	return binds && makefileNameMayBe(name, ".RECIPEPREFIX")
}

// MakefileRule describes a confirmed logical rule. Recipe holds the adjacent tab-prefixed
// commands in source order, including continuations. InlineRecipe is the separate semicolon command.
type MakefileRule struct {
	Targets       []string
	Prerequisites string
	InlineRecipe  string
	Recipe        []string
}

// MakefileRules yields declarations in source order up to the reader's logical-line and scanner
// bounds. It resolves each complete head with the bindings fixed by this file.
func MakefileRules(data string) iter.Seq[MakefileRule] {
	lines, _ := makefileLogicalLines(data)
	return makefileRules(lines, makefileReadVariables(lines))
}

// makefileRules visits syntax lines with the file's fixed bindings and stops where parsing is lost.
func makefileRules(lines []string, variables makefileVariables) iter.Seq[MakefileRule] {
	return func(yield func(MakefileRule) bool) {
		if slices.ContainsFunc(lines, makefileNamesRecipePrefix) {
			return
		}
		var scanner makefileScanner
		for index := 0; index < len(lines) && index < MaxMakefileLines; index++ {
			kind := scanner.next(lines[index])
			if scanner.lost {
				return
			}
			if kind != makefileSyntaxLine {
				continue
			}
			rule := makefileResolvedRule(lines, index, variables)
			if len(rule.Targets) > 0 && !yield(rule) {
				return
			}
		}
	}
}

// makefileResolvedRule reads a syntax line and the adjacent recipe lines belonging to its targets.
func makefileResolvedRule(lines []string, index int, variables makefileVariables) MakefileRule {
	line := lines[index]
	if makefileConditionalLine(line, strings.Fields(line)) {
		return MakefileRule{}
	}
	head, tail, ok := MakefileRuleParts(line)
	if !ok || makefileUncertainRule(line, tail) {
		return MakefileRule{}
	}
	names, _ := variables.targets(head, index)
	if len(names) == 0 {
		return MakefileRule{}
	}
	end := index + 1
	for end < len(lines) && end < MaxMakefileLines && strings.HasPrefix(lines[end], "\t") {
		end++
	}
	prereqs, inline := makefileRuleTailParts(tail)
	return MakefileRule{Targets: names, Prerequisites: prereqs, InlineRecipe: inline, Recipe: slices.Clone(lines[index+1 : end])}
}

// makefileRuleTailParts separates prerequisites from a comment or inline recipe at the first Make terminator.
func makefileRuleTailParts(tail string) (prereqs, inline string) {
	for i := 0; i < len(tail) && i < MaxMakefileLineBytes; {
		kind, width := makefileOperatorAt(tail, i)
		if kind == makefileEndToken {
			if tail[i] == ';' {
				return tail[:i], tail[i+1:]
			}
			return tail[:i], ""
		}
		i += width
	}
	return tail, ""
}

// makefileFindRule returns the first declaration that contains target.
func makefileFindRule(rules iter.Seq[MakefileRule], target string) (MakefileRule, bool) {
	for rule := range rules {
		if slices.Contains(rule.Targets, target) {
			return rule, true
		}
	}
	return MakefileRule{}, false
}

// MakefileTargetRecipe returns the tab-prefixed recipe lines, each ending in "\n", that follow
// the first rule data declares for target, and whether data declares one, as MakefileHasTarget
// reads it. A rule without recipe lines, such as "test: build" alone, returns an empty recipe. A
// recipe line continued with a backslash is returned with its continuation lines.
// data holds "\n" line endings: a caller normalizes a CRLF file first.
func MakefileTargetRecipe(data, target string) (string, bool) {
	rule, found := makefileFindRule(MakefileRules(data), target)
	if len(rule.Recipe) == 0 {
		return "", found
	}
	return strings.Join(rule.Recipe, "\n") + "\n", true
}

// makefileDirective returns the first word of a Makefile line that carries meaning, skipping the
// modifiers Make allows in front of a variable assignment or a define. "override", "export",
// "unexport" and "private" take an assignment or a "define" and nothing else, so none of them can
// introduce a rule; "override define recipe" is still a define.
func makefileDirective(fields []string) string {
	if index := makefileDirectiveIndex(fields); index < len(fields) {
		return fields[index]
	}
	return ""
}

// makefileDirectiveIndex returns the index of the first field that is not one of those modifiers,
// or len(fields) when every field is one.
func makefileDirectiveIndex(fields []string) int {
	for index, field := range fields {
		switch field {
		case "override", "export", "unexport", "private":
			continue
		}
		return index
	}
	return len(fields)
}

// makefileReadsFile reports whether fields, the words of a line, open a directive that makes Make
// read a file the reader does not see: an include, whose makefile may hold any line, or a load,
// whose object's setup may evaluate any text as makefile syntax through gmk_eval. Measured against
// GNU Make 4.4.1, "load ./rule.so" or "-load ./rule.so" with an object whose setup evaluates
// "verify-all: ; @echo custom" declares verify-all, and "load ./rebind.so" whose setup evaluates
// "NAME := build" between "NAME := verify-all" and "$(NAME):" declares build and no verify-all.
func makefileReadsFile(fields []string) bool {
	switch makefileDirective(fields) {
	case "include", "-include", "sinclude", "load", "-load":
		return true
	}
	return false
}

// makefileLineIsAmbiguous reports whether a line may define targets only Make can resolve: an
// include or a load (makefileReadsFile), a call that evaluates text (makefileCallsEval), a "!="
// binding, whose command output Make expands as makefile text (makefileBindsCommandOutput), a
// computed target name whose value the file does not fix (makefileVariables.targets) for the
// logical line at index, a pattern target name, or a rule whose prerequisites hold an assignment
// operator behind two or more words.
// Measured against GNU Make 4.4.1, Make reads "docs-lint: A B = x" as a rule with the
// prerequisites "A B = x" and stops at "docs-lint: A B := x" with "multiple target patterns", so
// the reader claims neither.
// The line is already trimmed and is neither a recipe line nor part of a define body. A define
// alone is not ambiguous: it only binds a variable, and makefileBareExpansion reports the lines
// that may expand it into rules. A bare modifier is not ambiguous either: measured against GNU
// Make 4.4.1, a Makefile holding "override verify-all := x" or "override CFLAGS += -Wall" beside an
// "all:" rule answers "make verify-all" with "No rule to make target".
func makefileLineIsAmbiguous(line string, index int, variables makefileVariables) bool {
	if strings.HasPrefix(line, "#") {
		return false
	}
	head, prerequisites, _ := MakefileRuleParts(line)
	if makefileUncertainRule(line, prerequisites) {
		return true
	}
	_, complete := variables.targets(head, index)
	return !complete
}

// makefileUncertainRule reports line-wide ambiguity from parsing computed text or an unnamed
// prerequisite assignment.
func makefileUncertainRule(line, prerequisites string) bool {
	_, unnamed := makefileAssignment(prerequisites)
	return unnamed || makefileParsesComputedText(strings.TrimSpace(line))
}

// MakefileMayDefineTarget reports whether data, the text of a Makefile with "\n" line endings,
// may already own target: a rule for it (MakefileHasTarget), a line only Make can resolve (an
// include, a load, an eval call, a "!=" binding, a computed target name whose value the file does
// not fix, a pattern target name), a top-level bare expansion other than silent calls
// (makefileBareExpansion, makefileSilentCalls), a tab-prefixed line Make parses as one of these
// because no recipe is open or may parse so in a branch it takes (makefileScanner), a mention of
// .RECIPEPREFIX, a define that is never closed, or a point the reader cannot resolve
// (makefileLogicalLines, makefileScanner), past which an unread line may hold any of these
// (HISS-02). A computed name the file fixes counts with its value: "$(OUT_DIR):" after "ROOT :=
// engine" and "OUT_DIR := $(ROOT)/out" declares engine/out and no docs-lint (makefileVariables). A
// caller about to append a rule for target must not when this reports true: Make would override
// one of the two recipes.
func MakefileMayDefineTarget(data, target string) bool {
	lines, whole := makefileLogicalLines(data)
	if !whole || slices.ContainsFunc(lines, makefileNamesRecipePrefix) {
		return true
	}
	variables := makefileReadVariables(lines)
	if _, found := makefileFindRule(makefileRules(lines, variables), target); found {
		return true
	}
	var scanner makefileScanner
	for index := 0; index < len(lines) && index < MaxMakefileLines; index++ {
		if makefileLeavesOwnershipToMake(&scanner, lines[index], index, variables) {
			return true
		}
	}
	return scanner.depth > 0
}
