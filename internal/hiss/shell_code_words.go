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
// Opaque reports whether the whole word is one of the caller's literal spans.
type ShellCodeWord struct {
	Code   string
	Text   string
	Value  string
	Opaque bool
}

// ShellCodeCommand is a program and its arguments, starting on the zero-based logical
// line in the source. Words start at the program after assignments and wrappers.
type ShellCodeCommand struct {
	Line  int
	Words []ShellCodeWord
}

// ShellCodeCommands reads the same shell code as ShellCode and retains source text for
// each word. The caller can mark opaque literal spans (start byte to exclusive end byte,
// in LF-normalized source) for text substituted by the script's host before the shell
// runs. Opaque spans contribute a single word fragment and cannot run shell commands.
func ShellCodeCommands(script string, maxLines int, literals map[int]int) ([]ShellCodeCommand, bool) {
	reader, ok := newShellCodeReader(script, maxLines)
	if !ok || !reader.maskLiterals(literals) {
		return nil, false
	}
	words := shellCodeWords{views: []*shellCodeView{{}}}
	reader.words = &words
	reader.read(nil)
	if !reader.readable() || words.overBound {
		return nil, false
	}
	return words.commands, true
}

// shellCodeView retains aligned code and source for the current command context.
type shellCodeView struct {
	code, source strings.Builder
	line         int
	literals     map[int]int
	removed      []int
}

func (v *shellCodeView) write(raw, code string) {
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

func (w *shellCodeWords) masked(raw string) {
	for _, view := range w.views {
		view.write(raw, "")
	}
}

func (w *shellCodeWords) markLiteral(width int) {
	if width == 0 {
		return
	}
	view := w.views[len(w.views)-1]
	if view.literals == nil {
		view.literals = make(map[int]int)
	}
	view.literals[view.source.Len()] = width
}

func (w *shellCodeWords) token(raw, code string, before *shellFrame, lexer *shellLexer, depth, line int) {
	if len(lexer.stack) > depth && shellReadsCommands(lexer.top()) {
		w.masked(raw)
		w.views = append(w.views, &shellCodeView{line: line})
		return
	}
	last := len(w.views) - 1
	if len(lexer.stack) < depth && shellReadsCommands(before) {
		w.flush(w.views[last])
		w.views = w.views[:last]
		w.masked(raw)
		return
	}
	for _, view := range w.views[:last] {
		view.write(raw, "")
	}
	view := w.views[last]
	drop := shellWordSyntax(raw, before, lexer.top(), len(lexer.stack)-depth)
	for i := 0; i < drop; i++ {
		view.removed = append(view.removed, view.source.Len()+i)
	}
	view.write(raw, code)
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

func shellLiteralQuote(frame *shellFrame) bool {
	return frame != nil && (frame.ctx == shellSingle || frame.ctx == shellDouble)
}

func shellEscapeRemovesSlash(frame *shellFrame, next byte) bool {
	return shellReadsCommands(frame) || frame.ctx == shellDouble && strings.IndexByte("\"\\$`", next) >= 0
}

func (w *shellCodeWords) newline(nextLine int, commands bool) {
	if !commands {
		w.masked("\n")
		return
	}
	last := len(w.views) - 1
	w.flush(w.views[last])
	w.views[last] = &shellCodeView{line: nextLine}
	for _, view := range w.views[:last] {
		view.write("\n", "")
	}
}

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
		words := view.sourceWords(cmd, start)
		w.commands = append(w.commands, ShellCodeCommand{Line: view.line, Words: words})
	}
}

func (v *shellCodeView) sourceWords(cmd shellCmd, start int) []ShellCodeWord {
	source := v.source.String()
	words := make([]ShellCodeWord, 0, len(cmd.words)-start)
	for i := start; i < len(cmd.words); i++ {
		code, at := cmd.words[i], cmd.at[i]
		words = append(words, ShellCodeWord{
			Code:   code,
			Text:   source[at : at+len(code)],
			Value:  v.spelling(at, at+len(code)),
			Opaque: v.literals[at] == len(code),
		})
	}
	return words
}

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
