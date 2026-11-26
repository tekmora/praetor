// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/util"
)

// renovateBodyOutline collects headings and task items outside code using the forge validator's
// task-list grammar. Ticking a copy lets the same matcher recognize an unchecked item.
func renovateBodyOutline(body string) (lines []string, receiptFence bool) {
	var fence util.MarkdownFence
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		wasOpen := fence.Open()
		if fence.Inside(trimmed) {
			if !wasOpen && isReceiptFence(trimmed) {
				receiptFence = true
			}
			continue
		}
		_, heading := util.MarkdownHeadingText(trimmed)
		if heading || checkedBoxRegex.MatchString(strings.Replace(trimmed, "[ ]", "[x]", 1)) {
			lines = append(lines, line)
		}
	}
	return lines, receiptFence
}

// renovateBodyParts lists Renovate's fields in their default rendering order.
var renovateBodyParts = [...]string{"header", "table", "warnings", "notes", "changelogs", "configDescription", "controls", "footer"}

// renovateDefaultBody is the exact block of unescaped fields expected in the summary.
var renovateDefaultBody = "{{{" + strings.Join(renovateBodyParts[:], "}}}{{{") + "}}}"

const (
	renovateControl = "- [ ] <!-- rebase-check --> If you want to rebase/retry this PR, check this box"
	renovateNote    = "Record any remaining CodeRabbit Description warning on the takeover pull request."
	renovateSummary = "## Summary of Changes"
)

// renderRenovateBody expands each configured field with sample Markdown, including Renovate's task item.
func renderRenovateBody(template string, notes []string) string {
	body := template
	for _, part := range renovateBodyParts {
		sample := "Sample " + part + "\n"
		switch part {
		case "notes":
			sample = strings.Join(notes, "\n\n") + "\n"
		case "controls":
			sample = "\n\n" + renovateControl + "\n\n"
		}
		body = strings.Replace(body, "{{{"+part+"}}}", sample, 1)
	}
	return body
}

// checkRenovateSummary verifies the complete source block and the visibility of the expanded note.
func checkRenovateSummary(template, body string) error {
	beforeRule, _, hasRule := strings.Cut(template, "\n---\n")
	_, summary, found := strings.Cut(beforeRule, "\n"+renovateSummary+"\n")
	if !hasRule || !found || strings.TrimSpace(summary) != renovateDefaultBody {
		return fmt.Errorf("Summary of Changes = %q, want %q", summary, renovateDefaultBody)
	}
	if strings.Contains(body, "{{{") {
		return fmt.Errorf("rendered body contains a surplus template field")
	}
	beforeRule, _, _ = strings.Cut(body, "\n---\n")
	if !hasVisibleRenovateNote(beforeRule) {
		return fmt.Errorf("rendered summary is missing the visible takeover note")
	}
	return nil
}

// hasVisibleRenovateNote follows comments and fences from the start of the body through the summary.
func hasVisibleRenovateNote(beforeRule string) bool {
	comments := util.CommentSyntax{Block: [][2]string{{"<!--", "-->"}}}
	var fence util.MarkdownFence
	var openComment string
	var inSummary bool
	for line := range strings.SplitSeq(beforeRule, "\n") {
		if !fence.Open() {
			line, openComment = util.StripComments(line, comments, openComment)
		}
		trimmed := strings.TrimSpace(line)
		if fence.Inside(trimmed) {
			continue
		}
		if trimmed == renovateSummary {
			inSummary = true
		}
		if inSummary && trimmed == renovateNote {
			return true
		}
	}
	return false
}

// checkRenovateOutline checks the rendered bot PR against the validator and the shipped outline.
func checkRenovateOutline(body string, wantOutline []string) error {
	result, err := ValidatePRChecklist(body)
	if err != nil {
		return err
	}
	// The bot leaves all mandatory checks and the receipt for the takeover author.
	unfilled, err := ValidatePRChecklist(renovateNote)
	if err != nil {
		return err
	}
	if !slices.Equal(result.Errors, unfilled.Errors) {
		return fmt.Errorf("rendered checklist findings = %q, want %q", result.Errors, unfilled.Errors)
	}
	got, fence := renovateBodyOutline(body)
	if fence {
		return fmt.Errorf("rendered body contains a receipt fence")
	}
	for _, line := range got {
		if checkedBoxRegex.MatchString(strings.TrimSpace(line)) {
			return fmt.Errorf("rendered body contains a checked box: %q", line)
		}
	}
	if !slices.Equal(got, wantOutline) {
		return fmt.Errorf("rendered outline = %q, want %q", got, wantOutline)
	}
	return nil
}

// checkRenovateBody checks the sample-expanded PR, the configured summary fields and the receipt text.
func checkRenovateBody(template string, notes, wantOutline []string) error {
	if !slices.Equal(notes, []string{renovateNote}) {
		return fmt.Errorf("prBodyNotes = %q, want only %q", notes, renovateNote)
	}
	body := renderRenovateBody(template, notes)
	if err := checkRenovateOutline(body, wantOutline); err != nil {
		return err
	}
	if err := checkRenovateSummary(template, body); err != nil {
		return err
	}
	const receipt = "The takeover pull request for `fix/renovate-<number>` carries the signed receipt."
	_, section, found := strings.Cut(body, wantOutline[len(wantOutline)-1]+"\n")
	if !found || strings.TrimSpace(section) != receipt {
		return fmt.Errorf("receipt section = %q, want %q", section, receipt)
	}
	return nil
}

// TestRenovatePRBody checks the configured notes, summary fields, repository outline and receipt.
// Its mutations distinguish a checkbox supplied by Renovate from the same text in the template.
func TestRenovatePRBody(t *testing.T) {
	var config struct {
		Template string   `yaml:"prBodyTemplate"`
		Notes    []string `yaml:"prBodyNotes"`
	}
	decodeConsumer(t, filepath.Join(engineCheckout, "renovate.json"), &config)
	want, _ := renovateBodyOutline(readTemplate(t))
	summary := slices.Index(want, renovateSummary)
	if summary < 0 {
		t.Fatal("shipped pull request template is missing the summary heading")
	}
	want = slices.Insert(want, summary+1, renovateControl)
	template, notes := config.Template, config.Notes
	moved := strings.Replace(template, renovateDefaultBody, "", 1)
	receiptHeading := want[len(want)-1]
	moved = strings.Replace(moved, receiptHeading, renovateDefaultBody+"\n\n"+receiptHeading, 1)
	for _, tc := range []struct {
		name, template string
		notes          []string
		valid          bool
	}{
		{"configured body with controls checkbox", template, notes, true},
		{"empty notes", template, []string{}, false},
		{"changed takeover note", template, []string{"Record the warning."}, false},
		{"additional note", template, append(slices.Clone(notes), "Another note."), false},
		{"default body without template sections", renovateDefaultBody, notes, false},
		{"parts moved before section 4", moved, notes, false},
		{"missing controls", strings.Replace(template, "{{{controls}}}", "", 1), notes, false},
		{"checked box", strings.Replace(template, "- [ ]", "- [x]", 1), notes, false},
		{"checked box after controls on the same line", strings.Replace(template, "{{{controls}}}", "{{{controls}}}- [x] HISS-16 verified\n", 1), notes, false},
		{"asterisk checked box", "* [x] HISS-16 verified\n\n" + template, notes, false},
		{"unrelated ordered checked box", "1) [X] already reviewed\n\n" + template, notes, false},
		{"extra unchecked asterisk box", "* [ ] Extra item\n\n" + template, notes, false},
		{"commented notes", strings.Replace(template, "{{{notes}}}", "<!-- {{{notes}}} -->", 1), notes, false},
		{"comment starts before summary", "<!--\n" + template, notes, false},
		{"second comment hides summary", "<!-- heading --> <!--\n" + template, notes, false},
		{"ninth summary field", strings.Replace(template, "{{{footer}}}", "{{{footer}}}{{{extra}}}", 1), notes, false},
		{"surplus field outside summary", "{{{extra}}}\n\n" + template, notes, false},
		{"body exceeds validator line limit", strings.Repeat("\n", MaxPRLinesLimit) + template, notes, false},
		{"added template box", strings.Replace(template, "{{{footer}}}", "{{{footer}}}\n\n"+renovateControl, 1), notes, false},
		{"empty receipt fence", "~~~receipt\n~~~\n\n" + template, notes, false},
		{"placeholder after receipt note", template + "\n{}", notes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRenovateBody(tc.template, tc.notes, want)
			if err == nil && !tc.valid {
				t.Error("accepted invalid Renovate pull request body")
			} else if err != nil && tc.valid {
				t.Fatal(err)
			}
		})
	}
}
