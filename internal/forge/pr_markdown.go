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
}

// parseChecklistDocument checks both PR body limits before allocating the Markdown tree.
func parseChecklistDocument(body string) (*checklistDocument, error) {
	if len(body) > maxReferenceTextBytes {
		return nil, fmt.Errorf("pull request body exceeds %d bytes", maxReferenceTextBytes)
	}
	// The PR limit counts the empty lines at EOF that CheckLineBudget normally trims.
	content := strings.TrimRight(body, "\n")
	trailing := len(body) - len(content)
	if err := util.CheckLineBudget(content, MaxPRLinesLimit-trailing); err != nil {
		return nil, fmt.Errorf("PR body exceeds %d lines", MaxPRLinesLimit)
	}
	source := []byte(body)
	return &checklistDocument{source: source, root: checklistParser.Parse(text.NewReader(source))}, nil
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
		case *ast.Heading:
			label, err := d.visibleText(block)
			if err != nil {
				return ast.WalkStop, err
			}
			res.outline = append(res.outline, strings.Repeat("#", block.Level)+" "+label)
		case *ast.Paragraph, *ast.TextBlock:
			return ast.WalkSkipChildren, d.readTask(n, res)
		case *ast.FencedCodeBlock:
			if _, closed := block.AttributeString("explicitClose"); !closed {
				line, _ := block.AttributeString("openingLine")
				res.Errors = append(res.Errors, fmt.Sprintf("close the code fence opened at line %d", line))
			}
			if receipt == nil && d.isReceipt(block) {
				receipt = block
			}
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
	if !ok {
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

// visibleText reads only text descendants. The goldmark writer resolves Markdown escapes
// and entities in ordinary text and preserves literal code. Remove its HTML escaping once.
func (d *checklistDocument) visibleText(block ast.Node) (string, error) {
	var encoded strings.Builder
	writer := bufio.NewWriter(&encoded)
	err := ast.Walk(block, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		t, ok := n.(*ast.Text)
		if !entering || !ok {
			return ast.WalkContinue, nil
		}
		value := t.Value(d.source)
		if t.IsRaw() {
			// CommonMark folds each line ending inside a code span to one space.
			line, endsLine := bytes.CutSuffix(value, []byte{'\n'})
			if endsLine {
				gmhtml.DefaultWriter.RawWrite(writer, bytes.TrimSuffix(line, []byte{'\r'}))
				return ast.WalkContinue, writer.WriteByte(' ')
			}
			gmhtml.DefaultWriter.RawWrite(writer, value)
		} else {
			gmhtml.DefaultWriter.Write(writer, value)
		}
		if t.SoftLineBreak() || t.HardLineBreak() {
			return ast.WalkContinue, writer.WriteByte('\n')
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
