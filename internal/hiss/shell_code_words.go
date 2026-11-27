// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hiss

import (
	"sort"
	"strings"
)

// ShellCodeWord pairs the masked code of a shell word with its source text after line
// splicing. Value removes POSIX quote and escape syntax without evaluating expansions.
type ShellCodeWord struct {
	Code  string
	Text  string
	Value string
	// Span contains the start and exclusive end byte offsets in the LF-normalized script.
	Span [2]int
}

// ShellCodeCommand is a program and its arguments, starting on the zero-based logical
// line in the source. Prefix retains the words skipped by invocation resolution,
// including command-local assignments and wrappers. Words start at the program.
type ShellCodeCommand struct {
	Line   int
	Prefix []ShellCodeWord
	Words  []ShellCodeWord
}

// ShellCodeCommands reads the same shell code as ShellCode and retains source text for
// each word. The caller can mark opaque literal spans (start byte to exclusive end byte,
// in LF-normalized source) for text substituted by the script's host before the shell
// runs. Opaque spans contribute a single word fragment and cannot run shell commands.
func ShellCodeCommands(script string, maxLines int, literals map[int]int) ([]ShellCodeCommand, bool) {
	source, ok := ReadShellCommandSource(script, maxLines, literals)
	return source.Commands, ok
}

// ShellCommandSource pairs resolved commands with the source intervals discarded as shell comments.
type ShellCommandSource struct {
	Commands []ShellCodeCommand
	Comments [][2]int
}

// ReadShellCommandSource retains locations so a caller can account for raw text the shell reader skipped.
func ReadShellCommandSource(script string, maxLines int, literals map[int]int) (ShellCommandSource, bool) {
	reader, ok := newShellCodeReader(script, maxLines)
	if !ok || !reader.maskLiterals(literals) {
		return ShellCommandSource{}, false
	}
	words := shellCodeWords{views: []*shellCodeView{{}}}
	reader.words = &words
	reader.read(nil)
	if !reader.readable() || words.overBound {
		return ShellCommandSource{}, false
	}
	return ShellCommandSource{Commands: words.commands, Comments: reader.comments}, true
}

// shellCodeView retains aligned code and source for the current command context.
type shellCodeView struct {
	code, source strings.Builder
	line         int
	removed      []int
	origins      []shellSourceOrigin
}

// shellSourceOrigin maps one contiguous part of a command view to its script byte offset.
type shellSourceOrigin struct {
	at, offset int
}

// offset translates a view byte to the script, accounting for splices and nested views.
func (v *shellCodeView) offset(at int) int {
	i := sort.Search(len(v.origins), func(i int) bool { return v.origins[i].at > at }) - 1
	return v.origins[i].offset + at - v.origins[i].at
}

// write appends raw source text and emitted code bytes to the view, padding code with placeholders to align lengths.
func (v *shellCodeView) write(raw, code string, offset int) {
	at := v.source.Len()
	if n := len(v.origins); n == 0 || v.origins[n-1].offset+at-v.origins[n-1].at != offset {
		v.origins = append(v.origins, shellSourceOrigin{at: at, offset: offset})
	}
	v.source.WriteString(raw)
	v.code.WriteString(code)
	for i := len(code); i < len(raw); i++ {
		v.code.WriteByte('_')
	}
}

// shellCodeWords keeps substitution commands separate from their enclosing word.
type shellCodeWords struct {
	views     []*shellCodeView
	commands  []ShellCodeCommand
	overBound bool
}

// masked writes raw source text into active views without emitting corresponding code tokens.
func (w *shellCodeWords) masked(raw string, offset int) {
	for _, view := range w.views {
		view.write(raw, "", offset)
	}
}

// token dispatches a scanned token to active views, tracking nesting depth and stripped quote syntax.
func (w *shellCodeWords) token(raw, code string, before *shellFrame, lexer *shellLexer, depth, line, offset int) {
	if len(lexer.stack) > depth && shellReadsCommands(lexer.top()) {
		w.masked(raw, offset)
		w.views = append(w.views, &shellCodeView{line: line})
		return
	}
	last := len(w.views) - 1
	if len(lexer.stack) < depth && shellReadsCommands(before) {
		w.flush(w.views[last])
		w.views = w.views[:last]
		w.masked(raw, offset)
		return
	}
	for _, view := range w.views[:last] {
		view.write(raw, "", offset)
	}
	view := w.views[last]
	drop := shellWordSyntax(raw, before, lexer.top(), len(lexer.stack)-depth)
	for i := 0; i < drop; i++ {
		view.removed = append(view.removed, view.source.Len()+i)
	}
	view.write(raw, code, offset)
}

// shellWordSyntax reports the leading bytes of a token that the lexer read as quote or
// escape syntax. Expansions keep their source spelling in the enclosing word.
func shellWordSyntax(raw string, before, after *shellFrame, change int) int {
	switch {
	case change > 0 && shellLiteralQuote(after) && shellReadsCommands(before):
		return len(raw)
	case change < 0 && shellLiteralQuote(before) && shellReadsCommands(after):
		return len(raw)
	case len(raw) == 2 && raw[0] == '\\' && shellEscapeRemovesSlash(before, raw[1]):
		return 1
	default:
		return 0
	}
}

// shellLiteralQuote reports whether the shell frame represents a single or double quote context.
func shellLiteralQuote(frame *shellFrame) bool {
	return frame != nil && (frame.ctx == shellSingle || frame.ctx == shellDouble)
}

// shellEscapeRemovesSlash reports whether an escaped backslash is stripped in the given frame context.
func shellEscapeRemovesSlash(frame *shellFrame, next byte) bool {
	return shellReadsCommands(frame) || frame.ctx == shellDouble && strings.IndexByte("\"\\$`", next) >= 0
}

// newline handles line boundary transitions by flushing completed views or masking newlines.
func (w *shellCodeWords) newline(nextLine, offset int, commands bool) {
	if !commands {
		w.masked("\n", offset)
		return
	}
	last := len(w.views) - 1
	w.flush(w.views[last])
	w.views[last] = &shellCodeView{line: nextLine}
	for _, view := range w.views[:last] {
		view.write("\n", "", offset)
	}
}

// flush parses accumulated view code into shell commands and appends resolved commands.
func (w *shellCodeWords) flush(view *shellCodeView) {
	commands := splitShellCommands(view.code.String())
	if len(commands) > maxShellCommands {
		w.overBound = true
		return
	}
	for _, cmd := range commands {
		invocation := resolveInvocation(cmd.words)
		if invocation.name == "" {
			continue
		}
		start := len(cmd.words) - len(invocation.args) - 1
		words := view.sourceWords(cmd, 0)
		var prefix []ShellCodeWord
		if start > 0 {
			prefix = words[:start:start]
		}
		w.commands = append(w.commands, ShellCodeCommand{
			Line: view.line, Prefix: prefix, Words: words[start:],
		})
	}
}

// sourceWords builds ShellCodeWord records for command arguments by extracting matched source and values.
func (v *shellCodeView) sourceWords(cmd shellCmd, start int) []ShellCodeWord {
	source := v.source.String()
	words := make([]ShellCodeWord, 0, len(cmd.words)-start)
	for i := start; i < len(cmd.words); i++ {
		code, at := cmd.words[i], cmd.at[i]
		words = append(words, ShellCodeWord{
			Code:  code,
			Text:  source[at : at+len(code)],
			Value: v.spelling(at, at+len(code)),
			Span:  [2]int{v.offset(at), v.offset(at+len(code)-1) + 1},
		})
	}
	return words
}

// spelling returns the source text between start and end with removed escape and quote characters excluded.
func (v *shellCodeView) spelling(start, end int) string {
	source := v.source.String()
	i := sort.SearchInts(v.removed, start)
	if i == len(v.removed) || v.removed[i] >= end {
		return source[start:end]
	}
	var value strings.Builder
	for ; i < len(v.removed) && v.removed[i] < end; i++ {
		value.WriteString(source[start:v.removed[i]])
		start = v.removed[i] + 1
	}
	value.WriteString(source[start:end])
	return value.String()
}
