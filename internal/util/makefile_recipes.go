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

// MakefileRecipeFile holds the literal rule names and recipe sources from one bounded read.
type MakefileRecipeFile struct {
	Targets map[string]bool
	Recipes []MakefileRecipe
}

// MakefileRecipes reads recipes using the default tab prefix and visits every conditional
// branch. Each recipe retains its backslash-newlines for the shell to interpret.
func MakefileRecipes(text string, maxLines int) (MakefileRecipeFile, error) {
	physical := strings.Split(strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n")
	if len(physical) > maxLines {
		return MakefileRecipeFile{}, fmt.Errorf("%s has %d lines, above the %d-line scan bound", makefileLabel, len(physical), maxLines)
	}
	file := MakefileRecipeFile{Targets: make(map[string]bool)}
	reader := makefileRecipeReader{targets: file.Targets}
	for start := 0; start < len(physical) && start < maxLines; {
		end, reason := makefileRecipeEnd(physical, start, maxLines)
		recipe, found, err := reader.readGroup(physical[start:end], start, reason)
		if err != nil {
			return MakefileRecipeFile{}, err
		}
		if found {
			file.Recipes = append(file.Recipes, recipe)
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
	targets map[string]bool
}

// readGroup preserves unread recipe text for the caller. A lost rule boundary can also
// change the interpretation of subsequent lines, so it invalidates the structural read.
func (s *makefileRecipeReader) readGroup(parts []string, start int, reason string) (MakefileRecipe, bool, error) {
	if reason != "" {
		if !s.inRecipe(parts[0]) {
			return MakefileRecipe{}, false, fmt.Errorf("%s:%d unverifiable test invocation: %s", makefileLabel, start+1, reason)
		}
		return MakefileRecipe{Line: start, Text: strings.Join(parts, "\n"), Unresolved: reason}, true, nil
	}
	recipe, found := s.recipeText(parts, start)
	if s.lost {
		return MakefileRecipe{}, false, fmt.Errorf("%s:%d unverifiable test invocation: unreadable recipe syntax", makefileLabel, start+1)
	}
	return recipe, found, nil
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
