// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hiss

import (
	"strings"

	"github.com/cordanaLLM/praetor/internal/util"
)

// The lexer the shell scanner (shell.go) reads code through.
//
// shellLexer turns each physical line of a POSIX shell or Bash script into its code. Quoted
// text, comments, parameter and arithmetic expansions and here-document bodies are blanked; a
// quote keeps its quote characters and an expansion becomes the placeholder "$_", so a word made
// of them is still a word but never a command name. The code inside a command substitution,
// $(...) or `...`, and a process substitution, <(...), is kept, even inside a double-quoted
// string, because it runs; a backquoted substitution is written as $(...). An arithmetic command
// such as for ((;;)) is kept as written. The state one line cannot hold carries to the next: an
// open quote or substitution, and a here-document waiting for its closing line.

const (
	// maxShellNesting bounds the stack of open quotes and substitutions (HISS-02).
	maxShellNesting = 32
	// maxShellHeredocs bounds the number of pending here-documents (HISS-02).
	maxShellHeredocs = 16
	// shellExpansion stands in for a parameter or arithmetic expansion.
	shellExpansion = "$_"
)

// shellContext is one kind of span the lexer can be inside.
type shellContext byte

const (
	shellCode shellContext = iota
	shellDouble
	shellSingle
	shellAnsi
	shellParam
	shellCommand
	shellBacktick
	shellArithExpansion
	shellArithCommand
)

// shellFrame is one open span: its kind and the brackets its own text opened.
type shellFrame struct {
	ctx   shellContext
	depth int
}

// shellHeredoc is a here-document whose body is still to be read.
type shellHeredoc struct {
	delimiter    string
	stripTabs    bool
	quoted       bool
	commandDepth int
}

// shellLexer carries the cross-line state of one script.
type shellLexer struct {
	stack []shellFrame
	word  bool
	// pending holds here-documents until a shell newline in their command context.
	pending []shellHeredoc
	// bodies holds the here-documents whose bodies are being read.
	bodies []shellHeredoc
	// bodyMatch is the delimiter prefix matched on a continued body line, or -1 on mismatch.
	bodyMatch int
	// portableHeredoc declines when physical and Bash-style delimiter matching disagree.
	portableHeredoc bool
	// misread records a construct the lexer could not follow: a delimiter it cannot read, or a
	// bound exceeded. The file is then declined.
	misread bool
}

// line returns the code of one physical line, or reports that the line belongs to a
// here-document body.
func (l *shellLexer) line(text string) (string, bool) {
	if len(l.bodies) > 0 {
		l.bodyLine(text, util.EndsWithUnescapedBackslash(text))
		return "", true
	}
	l.word = false
	var b strings.Builder
	for i := 0; i < len(text); {
		continued := i == len(text)-1 && text[i] == '\\' && shellReadsCommands(l.top())
		i = l.step(text, i, &b)
		if continued {
			return b.String(), false
		}
	}
	l.startBodies()
	return b.String(), false
}

// startBodies activates pending here-documents at a newline token in their command context.
func (l *shellLexer) startBodies() {
	if !shellReadsCommands(l.top()) {
		return
	}
	depth := len(l.stack)
	keep := l.pending[:0]
	for _, h := range l.pending {
		if h.commandDepth == depth {
			l.bodies = append(l.bodies, h)
		} else {
			keep = append(keep, h)
		}
	}
	l.pending = keep
}

// matchesPhysicalLine reports whether an unjoined line closes the here-document.
func (h shellHeredoc) matchesPhysicalLine(text string) bool {
	if h.stripTabs {
		text = strings.TrimLeft(text, "\t")
	}
	return text == h.delimiter
}

// bodyLine reads a physical body line. Unquoted delimiters are matched after joining
// backslash-newline pairs; only the matched prefix length needs to survive the join.
func (l *shellLexer) bodyLine(text string, spliced bool) {
	h := l.bodies[0]
	checkPhysical := l.portableHeredoc && !h.quoted
	physicalClose := checkPhysical && h.matchesPhysicalLine(text)
	continued := spliced && !h.quoted
	if continued {
		text = text[:len(text)-1]
	}
	l.matchBodyPrefix(h, text)
	joinedClose := !continued && l.bodyMatch == len(h.delimiter)
	if checkPhysical && physicalClose != joinedClose {
		l.misread = true
		return
	}
	if !continued {
		if joinedClose {
			l.bodies = l.bodies[1:]
		}
		l.bodyMatch = 0
	}
}

// matchBodyPrefix updates the delimiter match with one fragment of the joined body line.
func (l *shellLexer) matchBodyPrefix(h shellHeredoc, text string) {
	if h.stripTabs && l.bodyMatch == 0 {
		text = strings.TrimLeft(text, "\t")
	}
	if l.bodyMatch < 0 {
		return
	}
	if strings.HasPrefix(h.delimiter[l.bodyMatch:], text) {
		l.bodyMatch += len(text)
	} else {
		l.bodyMatch = -1
	}
}

// open reports whether a span or a here-document is still open.
func (l *shellLexer) open() bool {
	return len(l.stack) > 0 || len(l.pending) > 0 || len(l.bodies) > 0
}

func (l *shellLexer) top() *shellFrame {
	if len(l.stack) == 0 {
		return nil
	}
	return &l.stack[len(l.stack)-1]
}

func (l *shellLexer) push(ctx shellContext) {
	if len(l.stack) >= maxShellNesting {
		l.misread = true
		return
	}
	l.stack = append(l.stack, shellFrame{ctx: ctx})
}

func (l *shellLexer) pop() {
	// A substitution cannot leave pending bodies for another command context.
	if n := len(l.pending); n > 0 && l.pending[n-1].commandDepth == len(l.stack) {
		l.misread = true
	}
	l.stack = l.stack[:len(l.stack)-1]
}

// closeQuote ends the quoted span on top of the stack and writes its closing quote, unless the
// quote sat inside a parameter expansion, which is blanked whole.
func (l *shellLexer) closeQuote(quote byte, b *strings.Builder) {
	l.pop()
	l.word = true
	if frame := l.top(); frame == nil || frame.ctx != shellParam {
		b.WriteByte(quote)
	}
}

// step reads the token at i in the current span and returns the index past it.
func (l *shellLexer) step(text string, i int, b *strings.Builder) int {
	frame := l.top()
	if frame == nil {
		return l.code(text, i, b)
	}
	switch frame.ctx {
	case shellSingle:
		if text[i] == '\'' {
			l.closeQuote('\'', b)
		}
		return i + 1
	case shellAnsi:
		return l.ansi(text, i, b)
	case shellDouble:
		return l.double(text, i, b)
	case shellParam:
		return l.param(text, i, frame)
	case shellArithExpansion, shellArithCommand:
		return l.arith(text, i, frame, b)
	case shellBacktick:
		if text[i] == '`' {
			l.pop()
			l.word = true
			b.WriteByte(')')
			return i + 1
		}
	}
	return l.code(text, i, b)
}

// code reads one token of code: top-level code, or the code of a command or backquoted
// substitution.
func (l *shellLexer) code(text string, i int, b *strings.Builder) int {
	c := text[i]
	if l.startsComment(c) {
		return len(text)
	}
	l.word = strings.IndexByte(" \t;&|()<>", c) < 0
	switch c {
	case '\\':
		if i+1 >= len(text) {
			b.WriteByte('\\')
			return i + 1
		}
		b.WriteByte('_')
		return i + 2
	case '\'', '"', '`':
		return l.openQuote(c, i, b)
	case '$':
		return l.dollar(text, i, b)
	case '<', '>':
		return l.redirect(text, i, b)
	case '(', ')':
		return l.paren(text, i, b)
	}
	b.WriteByte(text[i])
	return i + 1
}

// startsComment reports whether the character c begins a shell comment given the current lexer state.
func (l *shellLexer) startsComment(c byte) bool {
	return c == '#' && !l.word && shellReadsCommands(l.top())
}

// shellReadsCommands reports whether the given frame is in a command-reading context rather than a quote or literal.
func shellReadsCommands(frame *shellFrame) bool {
	return frame == nil || frame.ctx == shellCommand || frame.ctx == shellBacktick
}

// openQuote opens a single-quoted, double-quoted or backquoted span.
func (l *shellLexer) openQuote(c byte, i int, b *strings.Builder) int {
	switch c {
	case '\'':
		l.push(shellSingle)
		b.WriteByte('\'')
	case '"':
		l.push(shellDouble)
		b.WriteByte('"')
	default:
		l.push(shellBacktick)
		l.word = false
		b.WriteString("$(")
	}
	return i + 1
}

// dollar reads an expansion that starts with $: an arithmetic or parameter expansion is
// blanked, a command substitution is kept as code, and $'...' and $"..." are quotes.
func (l *shellLexer) dollar(text string, i int, b *strings.Builder) int {
	rest := text[i+1:]
	switch {
	case strings.HasPrefix(rest, "$"):
		b.WriteString(shellExpansion)
		return i + 2
	case strings.HasPrefix(rest, "(("):
		l.push(shellArithExpansion)
		b.WriteString(shellExpansion)
		return i + 3
	case strings.HasPrefix(rest, "("):
		l.push(shellCommand)
		l.word = false
		b.WriteString("$(")
		return i + 2
	case strings.HasPrefix(rest, "{"):
		l.push(shellParam)
		b.WriteString(shellExpansion)
		return i + 2
	case strings.HasPrefix(rest, "'"):
		l.push(shellAnsi)
		b.WriteByte('\'')
		return i + 2
	case strings.HasPrefix(rest, `"`):
		l.push(shellDouble)
		b.WriteByte('"')
		return i + 2
	}
	b.WriteByte('$')
	return i + 1
}

// redirect reads a process substitution, a here-string or a here-document operator, or any
// other redirection byte.
func (l *shellLexer) redirect(text string, i int, b *strings.Builder) int {
	rest := text[i+1:]
	switch {
	case strings.HasPrefix(rest, "("):
		l.push(shellCommand)
		l.word = false
		b.WriteString(text[i : i+2])
		return i + 2
	case text[i] == '<' && strings.HasPrefix(rest, "<<"):
		b.WriteString("<<<")
		return i + 3
	case text[i] == '<' && strings.HasPrefix(rest, "<"):
		b.WriteString("<<")
		return l.heredoc(text, i+2)
	}
	b.WriteByte(text[i])
	return i + 1
}

// heredoc reads the delimiter word of a here-document whose operator ended at i and queues the
// body for the lines below.
func (l *shellLexer) heredoc(text string, i int) int {
	h := shellHeredoc{}
	if i < len(text) && text[i] == '-' {
		h.stripTabs = true
		i++
	}
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	delimiter, quoted, width, err := util.ShellHereDocDelimiter(text[i:])
	if err != nil || len(l.pending) >= maxShellHeredocs {
		l.misread = true
		return len(text)
	}
	h.delimiter = delimiter
	h.quoted = quoted
	h.commandDepth = len(l.stack)
	l.pending = append(l.pending, h)
	return i + width
}

// paren reads a parenthesis: (( opens an arithmetic command, and inside a command substitution
// the parentheses are counted so its own closing one is found.
func (l *shellLexer) paren(text string, i int, b *strings.Builder) int {
	frame := l.top()
	if text[i] == '(' && strings.HasPrefix(text[i+1:], "(") {
		l.push(shellArithCommand)
		b.WriteString("((")
		return i + 2
	}
	b.WriteByte(text[i])
	if frame == nil || frame.ctx != shellCommand {
		return i + 1
	}
	if text[i] == '(' {
		frame.depth++
	} else if frame.depth == 0 {
		l.pop()
		l.word = true
	} else {
		frame.depth--
	}
	return i + 1
}

// ansi reads $'...' text, where a backslash escapes the byte after it.
func (l *shellLexer) ansi(text string, i int, b *strings.Builder) int {
	if text[i] == '\\' {
		return i + 2
	}
	if text[i] == '\'' {
		l.closeQuote('\'', b)
	}
	return i + 1
}

// double reads double-quoted text, keeping the code of the substitutions inside it.
func (l *shellLexer) double(text string, i int, b *strings.Builder) int {
	switch text[i] {
	case '\\':
		return i + 2
	case '"':
		l.closeQuote('"', b)
		return i + 1
	case '`':
		return l.openQuote('`', i, b)
	case '$':
		if strings.HasPrefix(text[i+1:], "$") {
			return i + 2
		}
		if strings.HasPrefix(text[i+1:], "(") || strings.HasPrefix(text[i+1:], "{") {
			return l.dollar(text, i, b)
		}
	}
	return i + 1
}

// param reads the inside of ${...}, whose quotes and nested braces do not close it.
func (l *shellLexer) param(text string, i int, frame *shellFrame) int {
	switch text[i] {
	case '\\':
		return i + 2
	case '"':
		l.push(shellDouble)
	case '\'':
		l.push(shellSingle)
	case '{':
		frame.depth++
	case '}':
		if frame.depth == 0 {
			l.pop()
		} else {
			frame.depth--
		}
	}
	return i + 1
}

// arith reads an arithmetic expansion, which is blanked, or an arithmetic command, which is
// kept as written, up to the )) that closes it.
func (l *shellLexer) arith(text string, i int, frame *shellFrame, b *strings.Builder) int {
	keep := frame.ctx == shellArithCommand
	switch text[i] {
	case '(':
		frame.depth++
	case ')':
		if frame.depth > 0 {
			frame.depth--
			break
		}
		if strings.HasPrefix(text[i+1:], ")") {
			l.pop()
			if keep {
				b.WriteString("))")
			}
			return i + 2
		}
	}
	if keep {
		b.WriteByte(text[i])
	}
	return i + 1
}
