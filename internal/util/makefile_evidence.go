package util

import (
	"slices"
	"strings"
)

// MakefileEvidence describes the structural evidence for one target in the supplied Makefile.
type MakefileEvidence uint8

const (
	// MakefileTargetMissing means the reader found no rule for the target.
	MakefileTargetMissing MakefileEvidence = iota
	// MakefileTargetUnproven means the reader could not establish a literal rule with a body.
	MakefileTargetUnproven
	// MakefileTargetPresent means a literal rule supplies a prerequisite or recipe.
	MakefileTargetPresent
)

// MakefileTargetHasBody reports whether a literal rule provides evidence for target.
func MakefileTargetHasBody(data, target string) bool {
	return MakefileTargetStatus(data, target) == MakefileTargetPresent
}

// MakefileTargetStatus checks complete rules so a continued recipe can invalidate a literal head.
func MakefileTargetStatus(data, target string) MakefileEvidence {
	lines, whole := makefileTrackedLogicalLines(strings.TrimSuffix(data, "\n"), "")
	if slices.ContainsFunc(lines, func(line makefileTrackedLine) bool { return makefileNamesRecipePrefix(line.text) }) {
		return MakefileTargetUnproven
	}
	var reader makefileEvidenceReader
	for i := 0; i < len(lines) && i < MaxMakefileLines; i++ {
		kind := reader.scanner.next(lines[i].text)
		if reader.scanner.lost {
			return MakefileTargetUnproven
		}
		if reader.step(lines[i], kind, target) {
			return MakefileTargetPresent
		}
	}
	if !whole {
		return MakefileTargetUnproven
	}
	if reader.body {
		return MakefileTargetPresent
	}
	return reader.status
}

// makefileEvidenceReader keeps a pending rule until its last possible recipe line has been read.
type makefileEvidenceReader struct {
	scanner makefileScanner
	status  MakefileEvidence
	open    bool // An unconditional recipe line still belongs to this literal rule.
	body    bool // A literal prerequisite or unconditional literal recipe has been seen.
}

// step consumes one classified line and reports a proven rule once its recipe has ended.
func (r *makefileEvidenceReader) step(line makefileTrackedLine, kind int, target string) bool {
	switch {
	case kind == makefileRecipeLine || kind == makefileUnsureLine:
		r.recipe(line, kind)
	case kind == makefileSyntaxLine && r.scanner.targetOpen:
		// Blank lines, comments and conditional directives leave recipe ownership alone.
	default:
		if len(r.scanner.branches) == 0 && r.body {
			return true
		}
		r.open = false
		r.rule(line, target)
	}
	return false
}

// recipe vetoes continuations and counts literal commands whose ownership is certain.
func (r *makefileEvidenceReader) recipe(line makefileTrackedLine, kind int) {
	if line.continued && r.scanner.targetOpen {
		r.open, r.body = false, false
	} else if r.open && len(r.scanner.branches) == 0 && kind == makefileRecipeLine {
		r.body = r.body || makefileLiteralCommand(line.text)
	}
}

// rule records possible nonliteral declarations and starts a proof only for a literal rule.
func (r *makefileEvidenceReader) rule(line makefileTrackedLine, target string) {
	colon := r.scanner.ruleColon
	if colon < 0 {
		return
	}
	head := line.text[:colon]
	if makefileDirectiveWords[makefileDirective(strings.Fields(line.text))] {
		return
	}
	if !makefileLiteralWords(head) {
		r.status = MakefileTargetUnproven
		return
	}
	if !slices.Contains(strings.Fields(head), target) {
		return
	}
	r.status = MakefileTargetUnproven
	if len(r.scanner.branches) > 0 || line.continued || strings.Contains(line.text, "$") {
		return
	}
	r.open, r.body = makefileLiteralRuleTail(line.text[colon+1:])
	// The scanner tracks possible owners across branches for the continuation veto.
	r.scanner.targetOpen = r.open
}

// makefileLiteralWords accepts only Make word bytes and the horizontal blanks that separate them.
func makefileLiteralWords(text string) bool {
	for i := 0; i < len(text) && i < MaxMakefileLineBytes; i++ {
		if !makefileValueByte(text[i]) {
			return false
		}
	}
	return len(text) <= MaxMakefileLineBytes
}

// makefileLiteralRuleTail checks literal prerequisites on either side of the optional order-only
// separator and an optional inline recipe. It returns whether the head qualifies and has a body.
func makefileLiteralRuleTail(tail string) (literal, body bool) {
	code, _, _ := strings.Cut(tail, "#")
	prerequisites, command, _ := strings.Cut(code, ";")
	normal, orderOnly, _ := strings.Cut(prerequisites, "|")
	if !makefileLiteralWords(normal) || !makefileLiteralWords(orderOnly) {
		return false, false
	}
	words := strings.Fields(normal + " " + orderOnly)
	// GNU Make's .WAIT separates groups of prerequisites without naming one itself.
	hasPrerequisite := slices.ContainsFunc(words, func(word string) bool { return word != ".WAIT" })
	return true, hasPrerequisite || makefileLiteralCommand(command)
}

// makefileLiteralCommand requires command text after Make's recipe prefixes and before a comment.
func makefileLiteralCommand(text string) bool {
	command := strings.TrimSpace(strings.TrimLeft(text, " \t@-+"))
	return command != "" && command[0] != '#' && !strings.Contains(command, "$")
}
