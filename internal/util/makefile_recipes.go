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
	// GOFLAGSProblem describes a possible inherited export or why graph inference was refused.
	GOFLAGSProblem string
	owners         []string
}

// MakefileRecipeFile holds the literal rule names and sources from one bounded read.
type MakefileRecipeFile struct {
	Targets map[string]bool
	Recipes []MakefileRecipe
	// Immediate holds non-recipe source that can be expanded while Make reads the file.
	Immediate []MakefileRecipe
	// ShellAssignments holds the commands executed by != assignments while Make reads the file.
	ShellAssignments []MakefileRecipe
	// MayExportGOFLAGS reports a global GOFLAGS export or a blanket export mode.
	MayExportGOFLAGS bool
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
		if !found && reason == "" {
			reader.graph.readSourceExpansion(parts, inDefinition)
		}
		if found {
			reader.graph.readRecipeExpansion(recipe)
			file.Recipes = append(file.Recipes, recipe)
		} else if !inDefinition && reader.depth == 0 {
			makefileRecordTopLevelSource(&file, parts, start)
		}
		start = end
	}
	file.MayExportGOFLAGS = file.MayExportGOFLAGS || reader.blanketExport
	reader.graph.annotate(file.Recipes)
	return file, nil
}

// makefileRecordTopLevelSource records possible GOFLAGS exports, shell assignments,
// and immediate expansions from a top-level non-recipe group.
func makefileRecordTopLevelSource(file *MakefileRecipeFile, parts []string, start int) {
	file.MayExportGOFLAGS = file.MayExportGOFLAGS || makefileMayExportGOFLAGS(makefileJoinSyntax(parts))
	if command, ok := makefileShellAssignment(parts, start); ok {
		file.ShellAssignments = append(file.ShellAssignments, command)
	}
	if immediate, ok := makefileImmediateSource(parts, start); ok {
		file.Immediate = append(file.Immediate, immediate)
	}
}

// makefileMayExportGOFLAGS recognizes direct export directives without assuming
// that the deciding assignment is on the export line or before a recipe.
func makefileMayExportGOFLAGS(line string) bool {
	text := strings.TrimSpace(makefileImmediateSyntax(line))
	return makefileDirectExportsGOFLAGS(text)
}

// makefileDirectExportsGOFLAGS checks a trimmed line for a blanket or named export.
func makefileDirectExportsGOFLAGS(text string) bool {
	for strings.HasPrefix(text, "override ") || strings.HasPrefix(text, "override\t") {
		text = strings.TrimSpace(text[len("override"):])
	}
	if text == "export" {
		return true
	}
	if len(text) <= len("export") || !strings.HasPrefix(text, "export") || !strings.ContainsRune(" \t", rune(text[len("export")])) {
		return false
	}
	return makefileExportOperandsMayNameGOFLAGS(strings.TrimSpace(text[len("export"):]))
}

// makefileExportOperandsMayNameGOFLAGS checks the assignment name or export list
// following an export directive for a possible GOFLAGS name.
func makefileExportOperandsMayNameGOFLAGS(rest string) bool {
	if assign, colon, _ := makefileSplit(rest); assign >= 0 && (colon < 0 || assign < colon) {
		if names := makefileNameWords(rest[:assign]); len(names) == 1 {
			return makefileNameMayBe(names[0], "GOFLAGS")
		}
	}
	// Make expands the export list before splitting it into names. A reference
	// can introduce a separate GOFLAGS word even if it has literal affixes.
	if makefileSplitName(rest).computed {
		return true
	}
	for _, name := range strings.Fields(rest) {
		if name == "GOFLAGS" {
			return true
		}
	}
	return false
}

// maxMakefileGraphEntries bounds the Cartesian product of rule heads and
// prerequisites, independently of the physical and logical line limits.
const maxMakefileGraphEntries = 65536

const makefileExportGOFLAGSProblem = "cannot verify inherited GOFLAGS from Make exports"

type makefileGOFLAGSGraph struct {
	seeds               map[string]bool // true if at least one export can be inherited
	edges               map[string][]string
	phony               map[string]bool
	explicit            map[string]bool
	doubleColon         map[string]bool
	conditional         int
	entries             int
	seen                bool
	problem             string
	sourceEval          bool
	recipeReferenceLine int // one-based; zero means no Make reference was seen
}

// refuse records the first reason the literal graph cannot be trusted.
func (g *makefileGOFLAGSGraph) refuse(line int, reason string) {
	if g.problem == "" {
		g.problem = fmt.Sprintf("cannot resolve target graph for inherited GOFLAGS: %s:%d: %s", makefileLabel, line+1, reason)
	}
}

// makefileGraphName reports whether a name is a supported literal graph node.
func makefileGraphName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !makefileWordByte(name[i]) {
			return false
		}
	}
	return name != ""
}

// read uses the scanner's rule classification and the shared operator lexer.
// Unsupported syntax is remembered even before the first export is seen.
func (g *makefileGOFLAGSGraph) read(text string, names []string, prerequisites string, line int) {
	if text == "" || strings.HasPrefix(text, "#") {
		return
	}
	// Read bindings even after a refusal so a later export still sets seen.
	if g.readTargetBinding(text, line) || g.problem != "" {
		return
	}
	if makefileEvaluatesText(text) || makefileNamesRecipePrefix(text) {
		g.refuse(line, "Make syntax can change rule boundaries or dependencies")
		return
	}
	if names == nil {
		g.readGraphNonRule(text, line)
		return
	}
	g.readDependencies(names, prerequisites, line)
	// A recipe on one double-colon clause does not suppress implicit
	// search on another clause. Remember even conditional declarations.
	if _, colon, _ := makefileSplit(text); g.problem == "" && colon >= 0 && strings.HasPrefix(text[colon:], "::") {
		makefileMarkGraphNames(&g.doubleColon, names)
	}
}

// readTargetBinding separates target-specific assignments from ordinary rules and exports.
func (g *makefileGOFLAGSGraph) readTargetBinding(text string, line int) bool {
	if makefileExportDirective(text) {
		return false
	}
	assign, colon, _ := makefileSplit(text)
	offset := makefileTargetAssignmentStart(text, assign, colon)
	return offset != 0 && g.readBinding(text, offset, colon, line)
}

// readGraphNonRule checks directives and assignments that can affect dependency discovery.
func (g *makefileGOFLAGSGraph) readGraphNonRule(text string, line int) {
	if fields := strings.Fields(text); len(fields) != 0 {
		switch fields[0] {
		case "vpath", "include", "-include", "sinclude":
			g.refuse(line, "directive can change implicit prerequisite discovery")
		}
	}
	g.readGraphAssignment(text, line)
}

// readGraphAssignment rejects assignments that can alter dependency discovery.
func (g *makefileGOFLAGSGraph) readGraphAssignment(text string, line int) {
	name, bound := makefileBoundName(text)
	if bound && (makefileNameMayBe(name, ".EXTRA_PREREQS") || makefileNameMayBe(name, "VPATH") || makefileNameMayBe(name, "MAKEFLAGS") && !makefileGraphHarmlessFlags(text)) {
		g.refuse(line, "assignment can change the target graph")
	}
}

// makefileGraphUnsupportedTarget identifies nonliteral names and unsupported special targets.
func makefileGraphUnsupportedTarget(name string) bool {
	return !makefileGraphName(name) || strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "./") && name != ".PHONY"
}

// readDependencies validates and records ordinary and order-only prerequisites.
func (g *makefileGOFLAGSGraph) readDependencies(names []string, prerequisites string, line int) {
	for _, name := range names {
		if makefileGraphUnsupportedTarget(name) {
			g.refuse(line, "unsupported target "+name)
			return
		}
	}
	if _, _, _, end := makefileSplitSyntax(prerequisites); end >= 0 {
		prerequisites = prerequisites[:end]
	}
	deps := strings.Fields(strings.ReplaceAll(prerequisites, "|", " | "))
	for _, dep := range deps {
		if dep != "|" && !makefileGraphName(dep) {
			g.refuse(line, "unsupported prerequisite "+dep)
			return
		}
	}
	if !g.reserve(len(names), 1+len(deps), line) {
		return
	}
	if len(names) == 1 && names[0] == ".PHONY" {
		if g.conditional == 0 {
			makefileMarkGraphNames(&g.phony, deps)
		}
		return // its operands mark names, not build dependencies
	}
	g.addDependencies(names, deps)
}

func makefileMarkGraphNames(set *map[string]bool, names []string) {
	if *set == nil {
		*set = make(map[string]bool)
	}
	for _, name := range names {
		(*set)[makefileGraphKey(name)] = true
	}
}

func (g *makefileGOFLAGSGraph) recordRecipe(owners []string) {
	if g.problem == "" && g.conditional == 0 && len(owners) != 0 {
		// The owners have already been charged to the graph bound.
		makefileMarkGraphNames(&g.explicit, owners)
	}
}

// addDependencies adds normalized literal edges after the caller reserves their space.
func (g *makefileGOFLAGSGraph) addDependencies(names, deps []string) {
	if g.edges == nil {
		g.edges = make(map[string][]string)
	}
	for _, name := range names {
		name = makefileGraphKey(name)
		if _, exists := g.edges[name]; !exists {
			g.edges[name] = nil
		}
		for _, dep := range deps {
			if dep != "|" {
				g.edges[name] = append(g.edges[name], makefileGraphKey(dep))
			}
		}
	}
}

// makefileGraphHarmlessFlags reports whether a MAKEFLAGS assignment uses supported harmless flags.
func makefileGraphHarmlessFlags(text string) bool {
	assign, _, _ := makefileSplit(text)
	_, width := makefileOperatorAt(text, assign)
	return makefileHarmlessFlagsValue(text[assign:assign+width], text[assign+width:])
}

// reserve bounds graph storage before expanding a multi-target declaration.
func (g *makefileGOFLAGSGraph) reserve(names, perName, line int) bool {
	if names > (maxMakefileGraphEntries-g.entries)/perName {
		g.refuse(line, fmt.Sprintf("target graph exceeds the %d-entry bound", maxMakefileGraphEntries))
		return false
	}
	g.entries += names * perName
	return true
}

// makefileGraphKey normalizes leading current-directory prefixes for graph lookup.
func makefileGraphKey(name string) string {
	for strings.HasPrefix(name, "./") && len(name) > 2 {
		name = name[2:]
	}
	return name
}

// readBinding checks graph-changing assignments and records target-specific exports.
func (g *makefileGOFLAGSGraph) readBinding(text string, offset, colon, line int) bool {
	binding := text[offset:]
	name, bound := makefileBoundName(binding)
	if !bound {
		return false
	}
	if makefileEvaluatesText(text) || makefileNameMayBe(name, ".EXTRA_PREREQS") {
		g.refuse(line, "target-specific assignment can change the target graph")
	}
	if makefileNameMayBe(name, "GOFLAGS") {
		exported, private := makefileBindingExport(binding)
		if exported {
			g.seen = true
			g.addExportSeeds(strings.Fields(text[:colon]), private, line)
		}
	}
	return true
}

// makefileBindingExport reads export and private modifiers before the bound name.
func makefileBindingExport(binding string) (exported, private bool) {
	assign, _, _ := makefileSplit(binding)
	fields := strings.Fields(binding[:assign])
	for _, modifier := range fields[:makefileDirectiveIndex(fields)] {
		exported = exported || modifier == "export"
		private = private || modifier == "private"
	}
	return exported, private
}

// addExportSeeds records where GOFLAGS is exported and whether it can propagate.
func (g *makefileGOFLAGSGraph) addExportSeeds(names []string, private bool, line int) {
	if g.problem != "" || !g.reserve(len(names), 1, line) {
		return
	}
	if g.seeds == nil {
		g.seeds = make(map[string]bool)
	}
	for _, target := range names {
		if !makefileGraphName(target) {
			g.refuse(line, "unsupported GOFLAGS export target "+target)
			return
		}
		key := makefileGraphKey(target)
		g.seeds[key] = g.seeds[key] || !private
	}
}

// readSourceExpansion remembers eval outside recipes: a recursively expanded
// variable or define can defer that eval until a recipe references it.
func (g *makefileGOFLAGSGraph) readSourceExpansion(parts []string, inDefinition bool) {
	if g.sourceEval {
		return
	}
	text := makefileJoinSyntax(parts)
	if !inDefinition {
		text = makefileImmediateSyntax(text)
	}
	if strings.Contains(text, "$") {
		g.sourceEval = makefileRecipeCallsEval(makefileRecipeReferences(text, 0))
	}
}

func makefileRecipeCallsEval(recipe MakefileRecipe) bool {
	// These spans retain Make references, not the shell dollars produced from $$.
	for start, end := range recipe.LiteralSpans {
		if makefileCallsEval(recipe.Text[start:end]) {
			return true
		}
	}
	return false
}

// readRecipeExpansion refuses graph inference when recipe expansion may change exports.
func (g *makefileGOFLAGSGraph) readRecipeExpansion(recipe MakefileRecipe) {
	if g.recipeReferenceLine == 0 && len(recipe.LiteralSpans) != 0 {
		g.recipeReferenceLine = recipe.Line + 1
	}
	if makefileRecipeCallsEval(recipe) {
		g.seen = true
		g.refuse(recipe.Line, "recipe expansion may change GOFLAGS exports")
	}
}

// annotate marks recipes whose runtime GOFLAGS cannot be verified from the file.
func (g *makefileGOFLAGSGraph) annotate(recipes []MakefileRecipe) {
	// Do not resolve variable values or assume that the source eval was immediate.
	// Without a Make reference in a recipe, there is no such recipe-time path.
	if g.sourceEval && g.recipeReferenceLine != 0 {
		g.seen = true
		g.refuse(g.recipeReferenceLine-1, "recipe reference may invoke eval and change GOFLAGS exports")
	}
	if !g.seen {
		return
	}
	var inherited map[string]bool
	if g.problem == "" {
		inherited = g.inheritedTargets()
	}
	for i := range recipes {
		recipes[i].GOFLAGSProblem = g.recipeProblem(recipes[i].owners, inherited)
	}
}

// makefileImplicitFamily is a fallback for targets that can use implicit
// rules. Preserve the directory GNU Make puts back on prerequisites when
// matching slashless target patterns.
func makefileImplicitFamily(name string) string {
	i := strings.LastIndexByte(name, '/') + 1
	dir, base := name[:i], name[i:]
	for strings.HasPrefix(base, "s.") {
		base = base[2:]
	}
	stem, _, _ := strings.Cut(base, ".")
	stem, _, _ = strings.Cut(stem, ",")
	return dir + stem
}

// indexImplicitFamilies groups graph targets by possible implicit prerequisite family.
func (g *makefileGOFLAGSGraph) indexImplicitFamilies() map[string][]string {
	families := make(map[string][]string)
	for name := range g.edges {
		family := makefileImplicitFamily(name)
		families[family] = append(families[family], name)
		// Built-in terminal retrieval rules can use RCS/ and SCCS/
		// under the target's directory. Index these source names there too.
		if dir, base, ok := strings.Cut(family, "\x00"); ok {
			_ = dir
			_ = base
		}
		i := strings.LastIndexByte(name, '/') + 1
		dir, base := name[:i], name[i:]
		if parent, ok := strings.CutSuffix(dir, "RCS/"); ok && (parent == "" || strings.HasSuffix(parent, "/")) {
			key := makefileImplicitFamily(parent + base)
			families[key] = append(families[key], name)
		} else if parent, ok := strings.CutSuffix(dir, "SCCS/"); ok && (parent == "" || strings.HasSuffix(parent, "/")) {
			key := makefileImplicitFamily(parent + base)
			families[key] = append(families[key], name)
		}
	}
	return families
}

// inheritedTargets follows explicit edges and conservatively joins possible
// implicit prerequisite families. Each family is expanded at most once.
func (g *makefileGOFLAGSGraph) inheritedTargets() map[string]bool {
	families := g.indexImplicitFamilies()
	// Keep private seeds separate from the worklist: they are affected locally,
	// but only a non-private export or an incoming path starts propagation.
	inherited := make(map[string]bool)
	var queue []string
	push := func(name string) {
		if !inherited[name] {
			inherited[name] = true
			queue = append(queue, name)
		}
	}
	for name, propagates := range g.seeds {
		if propagates {
			push(name)
		}
	}
	for i := 0; i < len(queue); i++ {
		name := queue[i]
		for _, dep := range g.edges[name] {
			push(dep)
		}
		if g.phony[name] || g.explicit[name] && !g.doubleColon[name] {
			continue
		}
		family := makefileImplicitFamily(name)
		for _, candidate := range families[family] {
			push(candidate)
		}
		delete(families, family)
	}
	return inherited
}

// recipeProblem reports graph uncertainty or a possible export for the recipe owners.
func (g *makefileGOFLAGSGraph) recipeProblem(owners []string, inherited map[string]bool) string {
	if g.problem != "" {
		return g.problem
	}
	if len(owners) == 0 {
		return "cannot resolve recipe target for inherited GOFLAGS after a conditional"
	}
	for _, owner := range owners {
		key := makefileGraphKey(owner)
		if _, direct := g.seeds[key]; direct || inherited[key] {
			return makefileExportGOFLAGSProblem
		}
	}
	return ""
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
	targets                map[string]bool
	customPrefix           bool
	definitionMaySetPrefix bool
	blanketExport          bool
	owners                 []string
	graph                  makefileGOFLAGSGraph
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
		return MakefileRecipe{Line: start, Text: strings.Join(parts, "\n"), Unresolved: reason, owners: s.owners}, true, nil
	}
	if s.customPrefix {
		return makefileUnresolvedPrefixRecipe(parts, start), true, nil
	}
	if !s.inRecipe(parts[0]) && s.depth == 0 && makefileChangesRecipePrefix(makefileJoinSyntax(parts)) {
		s.customPrefix = true
		s.graph.refuse(start, "non-tab .RECIPEPREFIX prevents reading the target graph")
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

// makefileChangesRecipePrefix recognizes assignments that might select a non-tab prefix.
func makefileChangesRecipePrefix(line string) bool {
	if makefileComputedAssignmentMaySetRecipePrefix(line) {
		return true
	}
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

// makefileComputedAssignmentMaySetRecipePrefix reports whether an assignment
// with a reference in its name could set .RECIPEPREFIX.
func makefileComputedAssignmentMaySetRecipePrefix(line string) bool {
	assign, colon, ref := makefileSplit(line)
	if assign >= 0 && ref >= 0 && ref < assign && (colon < 0 || assign < colon) {
		names := makefileNameWords(line[:assign])
		return len(names) == 1 && makefileNameMayBe(names[0], ".RECIPEPREFIX")
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
	if recipe, found := s.tabbedRecipeText(parts, start); found {
		return recipe, true
	}
	syntax := makefileJoinSyntax(parts)
	depth := s.depth
	kind := s.nextWithDeferredDefinePrefix(syntax, true)
	s.trackDefinePrefix(syntax, depth, start)
	if kind != makefileSyntaxLine {
		if makefileDefineParsesText(syntax) {
			s.graph.refuse(start, "define may evaluate Make syntax")
		}
		return MakefileRecipe{}, false
	}
	trimmed := strings.TrimSpace(syntax)
	if s.readRecipeConditional(trimmed, start) {
		return MakefileRecipe{}, false
	}
	return s.ruleRecipeText(parts, syntax, trimmed, start)
}

// trackDefinePrefix records a possible prefix binding at a define opener and applies it at the close.
func (s *makefileRecipeReader) trackDefinePrefix(syntax string, previousDepth, start int) {
	switch {
	case previousDepth == 0 && s.depth != 0:
		name, bound := makefileBoundName(strings.TrimSpace(syntax))
		s.definitionMaySetPrefix = makefileMayBindRecipePrefix(syntax) || (bound && makefileNameMayBe(name, ".RECIPEPREFIX"))
	case previousDepth != 0 && s.depth == 0:
		if s.definitionMaySetPrefix {
			s.customPrefix = true
			s.graph.refuse(start, "non-tab .RECIPEPREFIX prevents reading the target graph")
		}
		s.definitionMaySetPrefix = false
	}
}

// tabbedRecipeText extracts a tabbed recipe and attaches its current rule owners.
func (s *makefileRecipeReader) tabbedRecipeText(parts []string, start int) (MakefileRecipe, bool) {
	if !s.inRecipe(parts[0]) {
		return MakefileRecipe{}, false
	}
	kind := s.next(parts[0])
	if kind != makefileRecipeLine && kind != makefileUnsureLine {
		return MakefileRecipe{}, false
	}
	recipe := makefileRecipeBody(parts, start)
	recipe.owners = s.owners
	if kind == makefileUnsureLine {
		s.graph.refuse(start, "conditional recipe boundary")
	} else {
		s.graph.recordRecipe(s.owners)
	}
	return recipe, true
}

// readRecipeConditional handles branch boundaries that can obscure recipe ownership.
func (s *makefileRecipeReader) readRecipeConditional(trimmed string, start int) bool {
	fields := strings.Fields(trimmed)
	if !makefileConditionalLine(trimmed, fields) {
		return false
	}
	// A recipe after a branch transition can belong to a different rule
	// even when the scanner says that a recipe is open in every branch.
	if fields[0] == "else" || fields[0] == "endif" {
		s.owners = nil
	}
	switch fields[0] {
	case "ifeq", "ifneq", "ifdef", "ifndef":
		s.graph.conditional++
	case "endif":
		s.graph.conditional--
	}
	if makefileEvaluatesText(trimmed) {
		s.graph.refuse(start, "conditional may evaluate Make syntax")
	}
	return true
}

// ruleRecipeText records a rule and extracts its inline recipe, if present.
func (s *makefileRecipeReader) ruleRecipeText(parts []string, syntax, trimmed string, start int) (MakefileRecipe, bool) {
	names, prerequisites := makefileRule(syntax)
	s.graph.read(trimmed, names, prerequisites, start)
	if names == nil {
		if s.recipe == makefileRecipeClosed {
			s.owners = nil
		}
		return MakefileRecipe{}, false
	}
	s.owners = names
	for _, name := range names {
		s.targets[name] = true
		if makefileGraphKey(name) == ".EXPORT_ALL_VARIABLES" {
			s.blanketExport = true
		}
	}
	recipe, found := makefileInlineRecipe(parts, start)
	recipe.owners = names
	if found {
		s.graph.recordRecipe(names)
	}
	return recipe, found
}

// makefileImmediateText keeps physical line offsets while exposing non-recipe continuations as whitespace.
func makefileImmediateText(parts []string) string {
	var logical strings.Builder
	for i, part := range parts {
		if i+1 < len(parts) {
			logical.WriteString(strings.TrimSuffix(part, "\\"))
			logical.WriteByte('\n')
		} else {
			logical.WriteString(part)
		}
	}
	return makefileImmediateSyntax(logical.String())
}

// makefileShellAssignment extracts only the command, not the variable name or operator.
func makefileShellAssignment(parts []string, start int) (MakefileRecipe, bool) {
	text := makefileImmediateText(parts)
	syntax := strings.ReplaceAll(text, "\n", " ")
	if makefileConditionalLine(syntax, strings.Fields(syntax)) {
		return MakefileRecipe{}, false
	}
	offset := makefileTargetAssignmentOffset(syntax)
	if offset != 0 && makefileExportDirective(syntax) {
		return MakefileRecipe{}, false
	}
	binding := syntax[offset:]
	assign, _, _ := makefileSplit(binding)
	if !makefileBindsVariable(binding) || len(makefileNameWords(binding[:assign])) != 1 || !strings.HasPrefix(binding[assign:], "!=") {
		return MakefileRecipe{}, false
	}
	// Leave expansions on the name side to the existing immediate-site check.
	// The command itself starts after the operator, possibly on a later physical line.
	end := offset + assign + len("!=")
	command := strings.TrimLeft(text[end:], " \t\n")
	start += strings.Count(text[:len(text)-len(command)], "\n")
	// A Make continuation becomes a space, not a shell command separator.
	// A space followed by a shell splice preserves that space and the physical line count.
	command = strings.ReplaceAll(command, "\n", " \\\n")
	return makefileRecipeReferences(command, start), true
}

// makefileImmediateSource collects candidate-bearing expansion sites without evaluating Make.
// An ordinary literal assignment is not a shell command, even with an immediate operator.
func makefileImmediateSource(parts []string, start int) (MakefileRecipe, bool) {
	text := makefileImmediateText(parts)
	if !strings.Contains(text, "$") {
		return MakefileRecipe{}, false
	}
	if end := makefileDeferredAssignment(text); end >= 0 {
		text = text[:end]
	}
	return makefileRecipeReferences(text, start), true
}

// makefileDeferredAssignment returns the offset of a deferred assignment operator,
// or -1 when the line does not bind a variable with = or ?=. The name side may
// still expand immediately. += depends on the variable's flavor, so keep its value.
func makefileDeferredAssignment(text string) int {
	// Use spaces for syntax checks but keep the same offsets as the physical source.
	syntax := strings.ReplaceAll(text, "\n", " ")
	offset := makefileTargetAssignmentOffset(syntax)
	syntax = syntax[offset:]
	assign, _, _ := makefileSplit(syntax)
	if assign < 0 || !makefileBindsVariable(syntax) || len(makefileNameWords(syntax[:assign])) != 1 {
		return -1
	}
	_, width := makefileOperatorAt(syntax, assign)
	switch syntax[assign : assign+width] {
	case "=", "?=":
		return offset + assign
	}
	return -1
}

// makefileTargetAssignmentOffset locates the text after a leading rule separator.
// Callers still have to establish that the suffix binds a variable.
func makefileTargetAssignmentOffset(syntax string) int {
	assign, colon, _ := makefileSplit(syntax)
	return makefileTargetAssignmentStart(syntax, assign, colon)
}

// makefileTargetAssignmentStart returns the offset after a rule separator preceding an assignment.
func makefileTargetAssignmentStart(syntax string, assign, colon int) int {
	if colon >= 0 && (assign < 0 || colon < assign) {
		_, width := makefileOperatorAt(syntax, colon)
		return colon + width
	}
	return 0
}

// makefileImmediateSyntax stops at the first unescaped top-level comment,
// leaving references and physical line offsets intact.
func makefileImmediateSyntax(text string) string {
	for i := 0; i < len(text); {
		switch text[i] {
		case '\\':
			i += makefileEscapeWidth(text, i)
		case '$':
			i += makefileReferenceWidth(text[i:])
		case '#':
			return text[:i]
		default:
			i++
		}
	}
	return text
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
