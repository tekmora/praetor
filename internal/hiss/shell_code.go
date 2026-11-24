// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hiss

import (
	"sort"
	"strings"

	"github.com/cordanaLLM/praetor/internal/util"
)

// ShellCode returns shell code in physical-line slots, with quotes, comments, expansions and
// here-document bodies blanked. A spliced line's code starts in the first slot of the join.
// ok is false if the line bound is exceeded or the lexer leaves a construct unreadable or open.
func ShellCode(script string, maxLines int) (lines []string, ok bool) {
	reader, ok := newShellCodeReader(script, maxLines)
	if !ok {
		return nil, false
	}
	lines = make([]string, len(reader.lines))
	reader.read(func(line int, code string) { lines[line] = code })
	if !reader.readable() {
		return nil, false
	}
	return lines, true
}

// shellCodeLine locates a physical line in the source and in the text with candidate splices
// removed. limit is the last physical line in its run of candidate splices.
type shellCodeLine struct {
	raw        string
	rawStart   int
	start, end int
	limit      int
	spliced    bool
}

// shellCodeReader uses the shell lexer for both the compact code and source-aligned commands.
// A comment ends at its original physical newline, even when the input joined across it.
type shellCodeReader struct {
	text     string
	code     string
	lines    []shellCodeLine
	physical int
	lex      shellLexer
	words    *shellCodeWords
	literals map[int]int
}

// newShellCodeReader constructs a shellCodeReader by splitting script lines and resolving backslash splices up to maxLines.
func newShellCodeReader(script string, maxLines int) (shellCodeReader, bool) {
	physical := strings.Split(strings.ReplaceAll(script, "\r\n", "\n"), "\n")
	if len(physical) > maxLines {
		return shellCodeReader{}, false
	}
	var flat strings.Builder
	lines := make([]shellCodeLine, len(physical))
	rawStart := 0
	for i, raw := range physical {
		spliced := i+1 < len(physical) && util.EndsWithUnescapedBackslash(raw)
		line := raw
		if spliced {
			line = raw[:len(raw)-1]
		}
		start := flat.Len()
		flat.WriteString(line)
		lines[i] = shellCodeLine{raw: raw, rawStart: rawStart, start: start, end: flat.Len(), spliced: spliced}
		rawStart += len(raw) + 1
	}
	for i := len(lines) - 1; i >= 0; i-- {
		lines[i].limit = i
		if lines[i].spliced {
			lines[i].limit = lines[i+1].limit
		}
	}
	text := flat.String()
	return shellCodeReader{text: text, code: text, lines: lines}, true
}

// readable reports whether the lexer finished without parsing errors or unclosed shell structures.
func (r *shellCodeReader) readable() bool {
	return !r.lex.misread && !r.lex.open()
}

// read steps through the physical lines once. Each scan advances to the last physical line
// actually read, which can be before the candidate join ends if a comment terminates it.
func (r *shellCodeReader) read(emit func(int, string)) {
	for r.physical < len(r.lines) && !r.lex.misread {
		start := r.physical
		if len(r.lex.bodies) > 0 {
			r.lex.bodyLine(r.lines[start].raw)
			r.finishLine()
		} else {
			code := r.scanLine()
			if emit != nil {
				emit(start, code)
			}
			r.lex.startBodies()
		}
		r.physical++
	}
}

// scanLine follows a possible splice run, stopping at the real newline of a shell comment.
func (r *shellCodeReader) scanLine() string {
	line := r.lines[r.physical]
	limit := r.lines[line.limit].end
	text := r.code[:limit]
	var code strings.Builder
	for i := line.start; i < limit && !r.lex.misread; {
		r.advanceSplices(i)
		if r.lex.startsComment(text[i]) {
			r.finishLine()
			return code.String()
		}
		i = r.scanToken(text, i, &code)
	}
	if !r.lex.misread {
		r.advanceSplices(limit)
		r.finishLine()
	}
	return code.String()
}

// advanceSplices advances the physical line index across backslash-spliced lines up to the given flat offset.
func (r *shellCodeReader) advanceSplices(at int) {
	for r.physical+1 < len(r.lines) && r.lines[r.physical].spliced && r.lines[r.physical].end <= at {
		if frame := r.lex.top(); frame != nil && frame.ctx == shellSingle && r.words != nil {
			r.words.masked("\\\n")
		}
		r.physical++
	}
}

// scanToken steps the lexer over the next token at index i, updating words and returning the next index.
func (r *shellCodeReader) scanToken(text string, i int, code *strings.Builder) int {
	depth, length, before := len(r.lex.stack), code.Len(), r.lex.top()
	next := min(r.lex.step(text, i, code), len(text))
	if r.words != nil {
		r.words.markLiteral(r.literals[i])
		r.words.token(r.text[i:next], code.String()[length:], before, &r.lex, depth, r.physical)
	}
	return next
}

// maskLiterals replaces opaque source spans with word bytes in the lexer's view only.
func (r *shellCodeReader) maskLiterals(literals map[int]int) bool {
	if len(literals) == 0 {
		return true
	}
	masked := []byte(r.text)
	r.literals = make(map[int]int, len(literals))
	previousEnd := 0
	for _, start := range util.SortedKeys(literals) {
		left, first := r.flatOffset(start)
		right, last := r.flatOffset(literals[start])
		if first < 0 || last < 0 || left < previousEnd || right <= left || last > r.lines[first].limit {
			return false
		}
		for i := left; i < right; i++ {
			masked[i] = '_'
		}
		r.literals[left] = right - left
		previousEnd = right
	}
	r.code = string(masked)
	return true
}

// flatOffset translates a raw script byte offset into flattened text coordinates and its physical line index.
func (r *shellCodeReader) flatOffset(raw int) (offset, physical int) {
	physical = sort.Search(len(r.lines), func(i int) bool { return r.lines[i].rawStart > raw }) - 1
	if physical < 0 {
		return 0, -1
	}
	line := r.lines[physical]
	if raw > line.rawStart+len(line.raw) {
		return 0, -1
	}
	return min(line.end, line.start+raw-line.rawStart), physical
}

// finishLine updates words and lexer state upon crossing a physical line boundary.
func (r *shellCodeReader) finishLine() {
	if r.words != nil {
		r.words.newline(r.physical+1, shellReadsCommands(r.lex.top()))
	}
	r.lex.word = !shellReadsCommands(r.lex.top())
}
