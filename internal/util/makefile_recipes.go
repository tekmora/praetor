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
}

// MakefileRecipes reads recipes using the default tab prefix and visits every conditional
// branch. Each recipe retains its backslash-newlines for the shell to interpret.
func MakefileRecipes(text string, maxLines int) ([]MakefileRecipe, error) {
	physical := strings.Split(strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n")
	if len(physical) > maxLines {
		return nil, fmt.Errorf("%s has %d lines, above the %d-line scan bound", makefileLabel, len(physical), maxLines)
	}
	reader := makefileScanner{}
	var recipes []MakefileRecipe
	for start := 0; start < len(physical) && start < maxLines; {
		end, err := makefileRecipeEnd(physical, start, maxLines)
		if err != nil {
			return nil, err
		}
		recipe, found := reader.recipeText(physical[start:end], start)
		if reader.lost {
			return nil, fmt.Errorf("%s:%d has unreadable recipe syntax", makefileLabel, start+1)
		}
		if found {
			recipes = append(recipes, recipe)
		}
		start = end
	}
	return recipes, nil
}

// makefileRecipeEnd returns the first physical line after the current logical line.
func makefileRecipeEnd(physical []string, start, maxLines int) (int, error) {
	limit := min(len(physical), maxLines)
	for i := start; i < limit; i++ {
		if !makefileContinues(physical[i]) {
			return i + 1, nil
		}
	}
	return limit, fmt.Errorf("%s:%d has an unfinished continuation", makefileLabel, limit)
}

// recipeText extracts a MakefileRecipe from tab-prefixed recipe lines or inline rule recipes.
func (s *makefileScanner) recipeText(parts []string, start int) (MakefileRecipe, bool) {
	if s.depth == 0 && strings.HasPrefix(parts[0], "\t") && s.recipe != makefileRecipeClosed {
		kind := s.next(parts[0])
		if kind == makefileRecipeLine || kind == makefileUnsureLine {
			return makefileRecipeBody(parts, start), true
		}
	}
	syntax := makefileJoinSyntax(parts)
	if s.next(syntax) != makefileSyntaxLine || makefileTargetNames(syntax) == nil {
		return MakefileRecipe{}, false
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
		case strings.HasPrefix(text[i:], "$("), strings.HasPrefix(text[i:], "${"):
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
