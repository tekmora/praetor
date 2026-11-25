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
	names := makefileAllowedRuleTargets(line, colon, makefileNames)
	if len(names) == 0 || !makefileLiteralWords(line[:colon]) {
		return false
	}
	literal, recipe := makefileLiteralRuleTail(line[colon+1:])
	if !literal || makefileEvidenceRefusesSpelling(names, target) {
		return false
	}
	r.inRule = true
	r.wanted = slices.Contains(names, target)
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

// makefileEvidenceRefusesSpelling reports a forbidden dot target or an alternate spelling of the requested target.
func makefileEvidenceRefusesSpelling(names []string, target string) bool {
	return slices.ContainsFunc(names, func(name string) bool {
		return makefileForbiddenDotTarget(name) || (name != target && makefileNormalizeName(name) == target)
	})
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
	prerequisites, command, _ := strings.Cut(tail, ";")
	prerequisites, _, comment := strings.Cut(prerequisites, "#")
	if comment {
		command = "" // A semicolon inside the Make comment cannot start an inline recipe.
	}
	normal, orderOnly, _ := strings.Cut(prerequisites, "|")
	literal = makefileLiteralWords(normal) && makefileLiteralWords(orderOnly) && !strings.Contains(command, "$")
	return literal, makefileLiteralCommand(command)
}

// makefileLiteralCommand requires command text after Make's recipe prefixes and before a comment.
func makefileLiteralCommand(text string) bool {
	command := strings.TrimSpace(strings.TrimLeft(text, " \t@-+"))
	return command != "" && command[0] != '#' && !strings.Contains(command, "$")
}
