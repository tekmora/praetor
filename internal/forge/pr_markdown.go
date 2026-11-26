// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"slices"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	task "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	gmutil "github.com/yuin/goldmark/util"

	"github.com/cordanaLLM/praetor/internal/util"
)

// checklistFenceParser observes the stock parser's explicit close event. CommonMark
// also ends a fence at EOF or a container boundary, but a signed receipt needs a closer.
type checklistFenceParser struct{ parser.BlockParser }

// Open saves the opening line for diagnostics on implicit closure.
func (p checklistFenceParser) Open(parent ast.Node, r text.Reader, pc parser.Context) (ast.Node, parser.State) {
	node, state := p.BlockParser.Open(parent, r, pc)
	if node != nil {
		line, _ := r.Position()
		node.SetAttributeString("openingLine", line+1)
	}
	return node, state
}

// Continue records a matching delimiter on the AST node before returning goldmark's decision.
func (p checklistFenceParser) Continue(n ast.Node, r text.Reader, pc parser.Context) parser.State {
	state := p.BlockParser.Continue(n, r, pc)
	if state == parser.Close {
		n.SetAttributeString("explicitClose", true)
	}
	return state
}

// Install the observer immediately before goldmark's default fenced block parser (priority 700).
var checklistParser = goldmark.New(
	goldmark.WithExtensions(extension.TaskList),
	goldmark.WithParserOptions(parser.WithBlockParsers(
		gmutil.Prioritized(checklistFenceParser{parser.NewFencedCodeBlockParser()}, 699),
	)),
).Parser()

// checklistDocument owns the bounded source bytes addressed by the AST's segments.
type checklistDocument struct {
	source []byte
	root   ast.Node
	hidden checklistRanges
}

// parseChecklistDocument returns a limit finding or the bounded Markdown tree.
func parseChecklistDocument(body string) (*checklistDocument, string) {
	if len(body) > maxReferenceTextBytes {
		return nil, fmt.Sprintf("pull request body exceeds %d bytes", maxReferenceTextBytes)
	}
	// The PR limit counts the empty lines at EOF that CheckLineBudget normally trims.
	content := strings.TrimRight(body, "\n")
	trailing := len(body) - len(content)
	if err := util.CheckLineBudget(content, MaxPRLinesLimit-trailing); err != nil {
		return nil, fmt.Sprintf("PR body exceeds %d lines", MaxPRLinesLimit)
	}
	source := []byte(body)
	root := checklistParser.Parse(text.NewReader(source))
	hidden, err := scanChecklistComments(source, root)
	if err != nil {
		return nil, err.Error()
	}
	return &checklistDocument{source: source, root: root, hidden: hidden}, ""
}

// readChecklist visits blocks in document order. Each heading or task paragraph consumes
// its own inline subtree once. Ordinary prose and fenced or HTML blocks supply no labels.
func (d *checklistDocument) readChecklist(res *PRChecklistResult) (string, error) {
	var receipt *ast.FencedCodeBlock
	err := ast.Walk(d.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch block := n.(type) {
		case *ast.Blockquote:
			return ast.WalkSkipChildren, nil
		case *ast.Heading:
			if d.hidden.contains(block.Pos()) {
				return ast.WalkSkipChildren, nil
			}
			label, err := d.visibleText(block)
			if err != nil {
				return ast.WalkStop, err
			}
			res.outline = append(res.outline, strings.Repeat("#", block.Level)+" "+label)
		case *ast.Paragraph, *ast.TextBlock:
			return ast.WalkSkipChildren, d.readTask(n, res)
		case *ast.FencedCodeBlock:
			receipt = d.readFence(block, receipt, res)
		default:
			return ast.WalkContinue, nil
		}
		return ast.WalkSkipChildren, nil
	})
	if err != nil {
		return "", fmt.Errorf("read PR checklist: %w", err)
	}
	res.receiptFence = receipt != nil
	return d.receiptText(receipt)
}

// readFence reports missing closers and selects the first visible receipt in source order.
func (d *checklistDocument) readFence(block, receipt *ast.FencedCodeBlock, res *PRChecklistResult) *ast.FencedCodeBlock {
	if d.hidden.contains(block.Pos()) {
		return receipt
	}
	if _, closed := block.AttributeString("explicitClose"); !closed {
		line, _ := block.AttributeString("openingLine")
		res.Errors = append(res.Errors, fmt.Sprintf("close the code fence opened at line %d", line))
	}
	if receipt == nil && d.isReceipt(block) {
		return block
	}
	return receipt
}

// receiptText extracts the first receipt, including when its payload is empty or invalid.
func (d *checklistDocument) receiptText(block *ast.FencedCodeBlock) (string, error) {
	if block == nil {
		return "", nil
	}
	if _, closed := block.AttributeString("explicitClose"); !closed {
		return "", fmt.Errorf("the Ed25519 Exit-0 receipt fence is never closed: end the receipt block with a matching fence")
	}
	return strings.TrimSpace(string(block.Lines().Value(d.source))), nil
}

// isReceipt matches a whole token anywhere in the parsed info string, including "json receipt".
func (d *checklistDocument) isReceipt(block *ast.FencedCodeBlock) bool {
	return block.Info != nil && slices.Contains(strings.Fields(strings.ToLower(string(block.Info.Value(d.source)))), ReceiptFenceToken)
}

// readTask credits only the first paragraph marked by the task-list extension. Goldmark
// also emits a checkbox for "[x]label", so enforce the checklist's separator at its AST position.
func (d *checklistDocument) readTask(n ast.Node, res *PRChecklistResult) error {
	box, ok := n.FirstChild().(*task.TaskCheckBox)
	if !ok || d.hidden.contains(box.Pos()) {
		return nil
	}
	after := box.Pos() + len("[x]")
	if after < len(d.source) && !gmutil.IsSpace(d.source[after]) {
		return nil
	}
	label, err := d.visibleText(n)
	if err != nil {
		return err
	}
	marker := "- [ ] "
	if box.IsChecked {
		marker = "- [x] "
		res.hasTickedBox = true
		res.recordCheckedLabel(label)
	}
	res.outline = append(res.outline, marker+label)
	return nil
}

// recordCheckedLabel matches required checks against the visible words of a ticked task.
func (res *PRChecklistResult) recordCheckedLabel(label string) {
	lower := strings.ToLower(strings.Join(strings.Fields(label), " "))
	if strings.Contains(lower, "hiss-16") || strings.Contains(lower, "compile-context") {
		res.HasHISS16Check = true
	}
	if strings.Contains(lower, "3d test") || strings.Contains(lower, "hiss-15") ||
		(strings.Contains(lower, "positive") && strings.Contains(lower, "negative")) {
		res.Has3DTestsCheck = true
	}
}

// visibleText reads rendered labels, including autolinks and literal code.
// The writer escapes its output as HTML, so unescape it once after flushing.
func (d *checklistDocument) visibleText(block ast.Node) (string, error) {
	var encoded strings.Builder
	writer := bufio.NewWriter(&encoded)
	err := ast.Walk(block, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch inline := n.(type) {
		case *ast.Image:
			return ast.WalkSkipChildren, nil
		case *ast.AutoLink:
			if !d.hidden.contains(inline.Pos()) {
				gmhtml.DefaultWriter.RawWrite(writer, inline.Label(d.source))
			}
		case *ast.Text:
			return ast.WalkContinue, d.writeVisibleText(writer, inline)
		}
		return ast.WalkContinue, nil
	})
	if err != nil {
		return "", fmt.Errorf("read Markdown text: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("flush Markdown text: %w", err)
	}
	return strings.TrimSpace(html.UnescapeString(encoded.String())), nil
}

// writeVisibleText preserves Markdown escapes, entities and code-span line folding.
func (d *checklistDocument) writeVisibleText(writer *bufio.Writer, t *ast.Text) error {
	value := d.hidden.visibleValue(t, d.source)
	if t.IsRaw() {
		line, endsLine := bytes.CutSuffix(value, []byte{'\n'})
		if endsLine {
			gmhtml.DefaultWriter.RawWrite(writer, bytes.TrimSuffix(line, []byte{'\r'}))
			return writer.WriteByte(' ')
		}
		gmhtml.DefaultWriter.RawWrite(writer, value)
	} else {
		gmhtml.DefaultWriter.Write(writer, value)
	}
	if (t.SoftLineBreak() || t.HardLineBreak()) && !d.hidden.contains(t.Segment.Stop) {
		return writer.WriteByte('\n')
	}
	return nil
}
