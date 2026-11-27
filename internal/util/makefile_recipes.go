// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package util

import (
	"fmt"
	"strings"
)

// makefileLabel names the file in recipe errors, as audit locations do (Makefile:<line>).
const makefileLabel = "Makefile"

// MakefileRecipe is one shell invocation's source in a Makefile, starting on Line (zero-based).
// LiteralSpans maps starts to exclusive ends of make references left opaque in Text.
type MakefileRecipe struct {
	Line         int
	Text         string
	LiteralSpans map[int]int
	// Unresolved names the reader limit or Make mode that prevents interpreting this source.
	Unresolved string
}

// MakefileRecipeFile holds the literal rule names and sources from one bounded read.
type MakefileRecipeFile struct {
	Targets map[string]bool
	Recipes []MakefileRecipe
	// Immediate holds non-recipe source that can be expanded while Make reads the file.
	Immediate []MakefileRecipe
}

// MakefileRecipes reads default-tab recipes and visits every conditional branch.
// After a possible non-tab .RECIPEPREFIX assignment, it preserves subsequent source
// as unresolved instead of trusting tab-based rule boundaries.
func MakefileRecipes(text string, maxLines int) (MakefileRecipeFile, error) {
	physical := strings.Split(strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n")
	if len(physical) > maxLines {
		return MakefileRecipeFile{}, fmt.Errorf("%s has %d lines, above the %d-line scan bound", makefileLabel, len(physical), maxLines)
	}
	file := MakefileRecipeFile{Targets: make(map[string]bool)}
	reader := makefileRecipeReader{targets: file.Targets}
	for start := 0; start < len(physical) && start < maxLines; {
		end, reason := makefileRecipeEnd(physical, start, maxLines)
		parts := physical[start:end]
		inDefinition := reader.depth != 0
		recipe, found, err := reader.readGroup(parts, start, reason)
		if err != nil {
			return MakefileRecipeFile{}, err
		}
		if found {
			file.Recipes = append(file.Recipes, recipe)
		} else if !inDefinition && reader.depth == 0 {
			if immediate, ok := makefileImmediateSource(parts, start); ok {
				file.Immediate = append(file.Immediate, immediate)
			}
		}
		start = end
	}
	return file, nil
}

// makefileRecipeEnd delimits the logical line before checking the bounds used by the Make syntax reader.
func makefileRecipeEnd(physical []string, start, maxLines int) (int, string) {
	limit := min(len(physical), maxLines)
	bytes := 0
	for i := start; i < limit; i++ {
		bytes += len(physical[i])
		if !makefileContinues(physical[i]) {
			switch {
			case bytes+i-start > MaxMakefileLineBytes:
				return i + 1, fmt.Sprintf("logical line exceeds the %d-byte reader bound", MaxMakefileLineBytes)
			case i-start > MaxMakefileContinuations:
				return i + 1, "logical line exceeds the continuation bound"
			}
			return i + 1, ""
		}
	}
	return limit, "unfinished continuation"
}

// makefileRecipeReader records literal rule names while classifying logical lines.
type makefileRecipeReader struct {
	makefileScanner
	targets      map[string]bool
	customPrefix bool
}

// readGroup preserves unread recipe text for the caller. A lost rule boundary can also
// change the interpretation of subsequent lines, so it invalidates the structural read.
func (s *makefileRecipeReader) readGroup(parts []string, start int, reason string) (MakefileRecipe, bool, error) {
	if reason != "" {
		if s.customPrefix {
			recipe := makefileUnresolvedPrefixRecipe(parts, start)
			recipe.Unresolved = reason
			return recipe, true, nil
		}
		if !s.inRecipe(parts[0]) {
			return MakefileRecipe{}, false, fmt.Errorf("%s:%d unverifiable test invocation: %s", makefileLabel, start+1, reason)
		}
		return MakefileRecipe{Line: start, Text: strings.Join(parts, "\n"), Unresolved: reason}, true, nil
	}
	if s.customPrefix {
		return makefileUnresolvedPrefixRecipe(parts, start), true, nil
	}
	if !s.inRecipe(parts[0]) && s.depth == 0 && makefileChangesRecipePrefix(makefileJoinSyntax(parts)) {
		s.customPrefix = true
		return MakefileRecipe{}, false, nil
	}
	recipe, found := s.recipeText(parts, start)
	if s.lost {
		return MakefileRecipe{}, false, fmt.Errorf("%s:%d unverifiable test invocation: unreadable recipe syntax", makefileLabel, start+1)
	}
	return recipe, found, nil
}

// makefileSkipAssignmentModifiers skips leading Make assignment modifiers.
func makefileSkipAssignmentModifiers(line string) string {
	line = strings.TrimLeft(line, " \t")
	// Each iteration that continues consumes at least one byte.
	limit := len(line)
	for step := 0; step < limit; step++ {
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			break
		}
		switch line[:end] {
		case "override", "export", "private":
			line = strings.TrimLeft(line[end+1:], " \t")
		default:
			return line
		}
	}
	return line
}

// makefileChangesRecipePrefix recognizes direct assignments that might select a non-tab prefix.
func makefileChangesRecipePrefix(line string) bool {
	rest, found := strings.CutPrefix(makefileSkipAssignmentModifiers(line), ".RECIPEPREFIX")
	if !found {
		return false
	}
	rest = strings.TrimLeft(rest, " \t")
	for _, op := range []string{":::=", "::=", ":=", "+=", "?=", "!=", "="} {
		if value, ok := strings.CutPrefix(rest, op); ok {
			value = strings.TrimLeft(value, " \t")
			return op == "!=" || (value != "" && value[0] != '#')
		}
	}
	return false
}

// makefileUnresolvedPrefixRecipe preserves candidate evidence without interpreting custom recipes.
// A possible prefix byte can occur at the start of any physical line in the group.
func makefileUnresolvedPrefixRecipe(parts []string, start int) MakefileRecipe {
	var text strings.Builder
	for i, part := range parts {
		if i > 0 {
			text.WriteByte('\n')
		}
		text.WriteString(part)
		if len(part) != 0 {
			text.WriteByte(';')
			text.WriteString(part[1:])
		}
	}
	recipe := makefileRecipeReferences(text.String(), start)
	recipe.Unresolved = "non-tab .RECIPEPREFIX prevents reading recipes"
	return recipe
}

// inRecipe reports whether a tab can introduce a recipe at this point in the file.
func (s *makefileRecipeReader) inRecipe(line string) bool {
	return s.depth == 0 && strings.HasPrefix(line, "\t") && s.recipe != makefileRecipeClosed
}

// recipeText extracts a tabbed or inline recipe and records the target names already read.
func (s *makefileRecipeReader) recipeText(parts []string, start int) (MakefileRecipe, bool) {
	if s.inRecipe(parts[0]) {
		kind := s.next(parts[0])
		if kind == makefileRecipeLine || kind == makefileUnsureLine {
			return makefileRecipeBody(parts, start), true
		}
	}
	syntax := makefileJoinSyntax(parts)
	if s.next(syntax) != makefileSyntaxLine {
		return MakefileRecipe{}, false
	}
	names := makefileTargetNames(syntax)
	if names == nil {
		return MakefileRecipe{}, false
	}
	for _, name := range names {
		s.targets[name] = true
	}
	return makefileInlineRecipe(parts, start)
}

// makefileImmediateSource collects candidate-bearing expansion sites without evaluating Make.
// An ordinary literal assignment is not a shell command, even with an immediate operator.
func makefileImmediateSource(parts []string, start int) (MakefileRecipe, bool) {
	// Keep physical line offsets, but treat non-recipe continuations as whitespace.
	var logical strings.Builder
	for i, part := range parts {
		if i+1 < len(parts) {
			logical.WriteString(strings.TrimSuffix(part, "\\"))
			logical.WriteByte('\n')
		} else {
			logical.WriteString(part)
		}
	}
	text := logical.String()
	text, syntax := makefileImmediateSyntax(text)
	if !strings.Contains(text, "$") {
		return MakefileRecipe{}, false
	}
	if eq := strings.IndexByte(string(syntax), '='); eq >= 0 {
		lhs := strings.TrimRight(string(syntax[:eq]), " \t\n")
		// += depends on the variable flavor. Treat it conservatively; plain =
		// and ?= do not expand their right-hand sides on assignment.
		if !strings.HasSuffix(lhs, ":") && !strings.HasSuffix(lhs, "!") && !strings.HasSuffix(lhs, "+") {
			text = text[:eq]
		}
	}
	return makefileRecipeReferences(text, start), true
}

// makefileImmediateSyntax masks references and stops at the first unescaped
// top-level comment without shifting source offsets.
func makefileImmediateSyntax(text string) (string, []byte) {
	syntax := []byte(text)
	limit := len(text)
	for i := 0; i < limit; {
		switch text[i] {
		case '\\':
			i += 2
		case '$':
			end := i + makefileReferenceWidth(text[i:])
			for j := i; j < end; j++ {
				syntax[j] = 'x'
			}
			i = end
		case '#':
			return text[:i], syntax[:i]
		default:
			i++
		}
	}
	return text, syntax
}

// makefileInlineRecipe parses an inline target rule recipe starting after a semicolon separator.
func makefileInlineRecipe(parts []string, start int) (MakefileRecipe, bool) {
	raw := strings.Join(parts, "\n")
	_, _, _, end := makefileSplitSyntax(raw)
	if end < 0 || raw[end] != ';' {
		return MakefileRecipe{}, false
	}
	start += strings.Count(raw[:end], "\n")
	return makefileRecipeBody(strings.Split(raw[end+1:], "\n"), start), true
}

// makefileRecipeBody strips leading tab indentation and recipe command prefixes, constructing a MakefileRecipe.
func makefileRecipeBody(parts []string, start int) MakefileRecipe {
	var shell strings.Builder
	for i, part := range parts {
		if i > 0 {
			shell.WriteByte('\n')
		}
		shell.WriteString(strings.TrimPrefix(part, "\t"))
	}
	return makefileRecipeReferences(strings.TrimLeft(shell.String(), " \t@-+"), start)
}

// makefileRecipeReferences resolves escaped dollars and keeps make references opaque. Shell
// substitutions use escaped dollars in recipes, so remain shell syntax after the expansion.
func makefileRecipeReferences(text string, start int) MakefileRecipe {
	recipe := MakefileRecipe{Line: start}
	var shell strings.Builder
	for i := 0; i < len(text); {
		switch {
		case strings.HasPrefix(text[i:], "$$"):
			shell.WriteByte('$')
			i += 2
		case text[i] == '$':
			end := i + makefileReferenceWidth(text[i:])
			if recipe.LiteralSpans == nil {
				recipe.LiteralSpans = make(map[int]int)
			}
			recipe.LiteralSpans[shell.Len()] = shell.Len() + end - i
			shell.WriteString(text[i:end])
			i = end
		default:
			shell.WriteByte(text[i])
			i++
		}
	}
	recipe.Text = shell.String()
	return recipe
}
