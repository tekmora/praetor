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
	// MakefileTargetPresent means a literal rule supplies a literal recipe.
	MakefileTargetPresent
)

// MakefileTargetHasBody reports whether a literal rule provides evidence for target.
func MakefileTargetHasBody(data, target string) bool {
	return MakefileTargetStatus(data, target) == MakefileTargetPresent
}

// MakefileTargetStatus requires one declaration with a literal recipe in a fully understood file.
func MakefileTargetStatus(data, target string) MakefileEvidence {
	lines, whole := makefileTrackedLogicalLines(strings.TrimSuffix(data, "\n"), "")
	if !whole {
		return MakefileTargetUnproven
	}
	var reader makefileEvidenceReader
	for i := 0; i < len(lines) && i < MaxMakefileLines; i++ {
		line := lines[i]
		if line.continued || strings.ContainsAny(line.text, "\x00\r\ufeff") || !reader.accept(line.text, target) {
			return MakefileTargetUnproven
		}
	}
	return reader.status
}

// makefileEvidenceReader tracks recipe ownership and the one declaration of the requested target.
type makefileEvidenceReader struct {
	status MakefileEvidence
	inRule bool
	wanted bool
}

// accept consumes one allowed physical line. Blank lines and comments preserve recipe ownership.
func (r *makefileEvidenceReader) accept(line, target string) bool {
	trimmed := strings.Trim(line, " \t")
	switch {
	case trimmed == "" || strings.HasPrefix(trimmed, "#"):
		return true
	case strings.HasPrefix(line, "\t") && r.inRule:
		if r.wanted && makefileLiteralCommand(line) {
			r.status = MakefileTargetPresent
		}
		return true
	}
	r.inRule, r.wanted = false, false
	if makefileEvidenceDirective(trimmed) {
		return false
	}
	return r.declaration(line, target)
}

// makefileEvidenceDirective identifies includes, conditionals, define blocks and variable modifiers.
func makefileEvidenceDirective(line string) bool {
	fields := strings.Fields(line)
	return len(fields) == 0 || makefileDirectiveIndex(fields) != 0 ||
		makefileDirectiveWords[fields[0]] || makefileConditionalWords[fields[0]]
}

// declaration distinguishes simple assignments from literal rules by their first Make operator.
func (r *makefileEvidenceReader) declaration(line, target string) bool {
	assign, colon, _ := makefileSplit(line)
	if assign >= 0 && (colon < 0 || assign < colon) {
		name := strings.Trim(line[:assign], " \t")
		return makefileMatchesIdentifier(name) && !makefileEvidenceDirective(name) && makefileAllowedAssignment(line, assign)
	}
	return colon > 0 && line[0] != '\t' && r.rule(line, colon, target)
}

// rule validates every rule and refuses a second declaration, including one in a target list.
func (r *makefileEvidenceReader) rule(line string, colon int, target string) bool {
	head := strings.Trim(line[:colon], " \t")
	if head == "" || !makefileLiteralWords(head) || strings.Contains(line, "$") {
		return false
	}
	literal, recipe := makefileLiteralRuleTail(line[colon+1:])
	if !literal {
		return false
	}
	names := strings.Fields(head)
	r.inRule = true
	r.wanted = slices.Contains(names, target)
	// A different spelling of the same path can replace this target's recipe.
	if slices.ContainsFunc(names, func(name string) bool {
		return name != target && makefileNormalizeName(name) == target
	}) {
		return false
	}
	if r.wanted {
		if r.status != MakefileTargetMissing {
			return false
		}
		r.status = MakefileTargetUnproven
		if recipe {
			r.status = MakefileTargetPresent
		}
	}
	return true
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
// separator and reports whether the rule also has a literal inline command.
func makefileLiteralRuleTail(tail string) (literal, recipe bool) {
	code, _, _ := strings.Cut(tail, "#")
	prerequisites, command, _ := strings.Cut(code, ";")
	normal, orderOnly, _ := strings.Cut(prerequisites, "|")
	return makefileLiteralWords(normal) && makefileLiteralWords(orderOnly), makefileLiteralCommand(command)
}

// makefileLiteralCommand requires command text after Make's recipe prefixes and before a comment.
func makefileLiteralCommand(text string) bool {
	command := strings.TrimSpace(strings.TrimLeft(text, " \t@-+"))
	return command != "" && command[0] != '#' && !strings.Contains(command, "$")
}
