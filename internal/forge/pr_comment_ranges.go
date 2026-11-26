// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// checklistRanges holds disjoint, half-open byte ranges in source order.
type checklistRanges []text.Segment

// firstAfter finds the first range with bytes at or after the offset.
func (r checklistRanges) firstAfter(offset int) int {
	return sort.Search(len(r), func(i int) bool { return r[i].Stop > offset })
}

// contains reports whether the byte at offset belongs to a range.
func (r checklistRanges) contains(offset int) bool {
	i := r.firstAfter(offset)
	return i < len(r) && r[i].Start <= offset
}

// commentSources distinguishes Markdown prose (where backslashes escape punctuation)
// from raw HTML. Literal code, link destinations and image attributes supply neither.
type commentSources struct {
	prose checklistRanges
	html  checklistRanges
}

// commentOpenerRanges indexes the source segments that can introduce a comment.
func commentOpenerRanges(root ast.Node, source []byte) (commentSources, error) {
	var ranges commentSources
	err := ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Image:
			return ast.WalkSkipChildren, nil
		case *ast.Text:
			if !n.IsRaw() {
				ranges.prose = append(ranges.prose, n.Segment)
			}
		case *ast.RawHTML:
			first := n.Segments.At(0)
			if bytes.HasPrefix(source[first.Start:first.Stop], []byte("<!--")) {
				ranges.html = append(ranges.html, first)
			}
		case *ast.HTMLBlock:
			lines := n.Lines()
			ranges.html = append(ranges.html, lines.Sliced(0, lines.Len())...)
			if n.HasClosure() {
				ranges.html = append(ranges.html, n.ClosureLine)
			}
		}
		return ast.WalkContinue, nil
	})
	if err != nil {
		return commentSources{}, fmt.Errorf("locate comment openers: %w", err)
	}
	return ranges, nil
}

// canOpen accepts a raw HTML opener or an unescaped opener in Markdown prose.
func (r commentSources) canOpen(source []byte, start int) bool {
	if r.html.contains(start) {
		return true
	}
	if !r.prose.contains(start) {
		return false
	}
	i := start
	for i > 0 && source[i-1] == '\\' {
		i--
	}
	return (start-i)%2 == 0
}

// scanChecklistComments pairs each opener with the next raw closer or EOF.
// Once open, a comment can cross any number of lines and Markdown blocks.
func scanChecklistComments(source []byte, root ast.Node) (checklistRanges, error) {
	const opener, closer = "<!--", "-->"
	if !bytes.Contains(source, []byte(opener)) {
		return nil, nil
	}
	candidates, err := commentOpenerRanges(root, source)
	if err != nil {
		return nil, err
	}
	var hidden checklistRanges
	for pos := 0; pos < len(source); {
		offset := bytes.Index(source[pos:], []byte(opener))
		if offset < 0 {
			break
		}
		start := pos + offset
		pos = start + len(opener)
		if !candidates.canOpen(source, start) {
			continue
		}
		end := bytes.Index(source[pos:], []byte(closer))
		if end < 0 {
			pos = len(source)
		} else {
			pos += end + len(closer)
		}
		hidden = append(hidden, text.NewSegment(start, pos))
	}
	return hidden, nil
}

// visibleValue retains the visible parts of a text segment crossing a comment boundary.
func (r checklistRanges) visibleValue(t *ast.Text, source []byte) []byte {
	seg := t.Segment
	i := r.firstAfter(seg.Start)
	if i == len(r) || r[i].Start >= seg.Stop {
		return t.Value(source)
	}
	var visible []byte
	for ; i < len(r) && r[i].Start < seg.Stop; i++ {
		if seg.Start < r[i].Start {
			visible = append(visible, source[seg.Start:r[i].Start]...)
		}
		seg.Start = min(r[i].Stop, seg.Stop)
	}
	return append(visible, source[seg.Start:seg.Stop]...)
}
