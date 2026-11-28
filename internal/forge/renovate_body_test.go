// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yuin/goldmark/ast"

	"github.com/cordanaLLM/praetor/internal/util"
)

// renovateBodyParts pins the fields declared inline in renovate.json's prBodyTemplate.
// The source check and the sample renderer share this ordered list.
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

// checkRenovateTemplate permits exactly the configured field block before sample expansion.
func checkRenovateTemplate(template string) error {
	beforeRule, _, hasRule := strings.Cut(template, "\n---\n")
	_, summary, found := strings.Cut(beforeRule, "\n"+renovateSummary+"\n")
	if !hasRule || !found || strings.TrimSpace(summary) != renovateDefaultBody {
		return fmt.Errorf("Summary of Changes = %q, want %q", summary, renovateDefaultBody)
	}
	if strings.Contains(strings.Replace(template, renovateDefaultBody, "", 1), "{{") {
		return fmt.Errorf("unexpected Handlebars expression outside the configured summary fields")
	}
	return nil
}

// checkRenovateNote looks for the visible note in the bounded, rendered summary.
func checkRenovateNote(body string) error {
	beforeRule, _, _ := strings.Cut(body, "\n---\n")
	doc, finding := parseChecklistDocument(beforeRule)
	if finding != "" {
		return errors.New(finding)
	}
	inSummary := false
	block := doc.root.FirstChild()
	for range doc.root.ChildCount() {
		heading := block.Kind() == ast.KindHeading
		if (heading && !doc.hidden.contains(block.Pos())) || block.Kind() == ast.KindParagraph {
			label, err := doc.visibleText(block)
			if err != nil {
				return err
			}
			if heading {
				inSummary = label == strings.TrimPrefix(renovateSummary, "## ")
			} else if inSummary && slices.Contains(strings.Split(label, "\n"), renovateNote) {
				return nil
			}
		}
		block = block.NextSibling()
	}
	return fmt.Errorf("rendered summary is missing the visible takeover note")
}

// checkRenovateOutline checks the rendered bot PR against the validator and the shipped outline.
func checkRenovateOutline(body string, wantOutline []string) error {
	result, err := ValidatePRChecklist(body)
	if err != nil {
		if result != nil {
			return fmt.Errorf("validate rendered checklist: %w: %v", err, result.Errors)
		}
		return err
	}
	if result.hasTickedBox {
		return fmt.Errorf("rendered body contains a checked box")
	}
	// The bot leaves all mandatory checks and the receipt for the takeover author.
	unfilled, err := ValidatePRChecklist(renovateNote)
	if err != nil {
		return err
	}
	if !slices.Equal(result.Errors, unfilled.Errors) {
		return fmt.Errorf("rendered checklist findings = %q, want %q", result.Errors, unfilled.Errors)
	}
	if result.receiptFence {
		return fmt.Errorf("rendered body contains a receipt fence")
	}
	if !slices.Equal(result.outline, wantOutline) {
		return fmt.Errorf("rendered outline = %q, want %q", result.outline, wantOutline)
	}
	return nil
}

// checkRenovateBody checks the sample-expanded PR, the configured summary fields and the receipt text.
func checkRenovateBody(template string, notes, wantOutline []string) error {
	if !slices.Equal(notes, []string{renovateNote}) {
		return fmt.Errorf("prBodyNotes = %q, want only %q", notes, renovateNote)
	}
	if err := checkRenovateTemplate(template); err != nil {
		return err
	}
	body := renderRenovateBody(template, notes)
	if err := checkRenovateOutline(body, wantOutline); err != nil {
		return err
	}
	// The configured prefix contains exactly the shipped title.
	beforeSummary, _, _ := strings.Cut(template, "\n"+renovateSummary+"\n")
	if strings.TrimSpace(beforeSummary) != wantOutline[0] {
		return fmt.Errorf("unexpected content before the summary heading")
	}
	if err := checkRenovateNote(body); err != nil {
		return err
	}
	const receipt = "The takeover pull request for `fix/renovate-<number>` carries the signed receipt."
	_, section, found := strings.Cut(body, wantOutline[len(wantOutline)-1]+"\n")
	if !found || strings.TrimSpace(section) != receipt {
		return fmt.Errorf("receipt section = %q, want %q", section, receipt)
	}
	return nil
}

// renovateTemplateOutline reads the shipped outline and inserts Renovate's visible
// task item where the configured fields render it.
func renovateTemplateOutline(shipped string) ([]string, error) {
	if err := util.CheckLineBudget(shipped, MaxPRLinesLimit); err != nil {
		return nil, err
	}
	template, err := ValidatePRChecklist(shipped)
	if err != nil {
		return nil, err
	}
	summary := slices.Index(template.outline, renovateSummary)
	if summary < 0 {
		return nil, fmt.Errorf("shipped pull request template is missing the summary heading: %v", template.Errors)
	}
	control, err := ValidatePRChecklist(renovateControl)
	if err != nil {
		return nil, err
	}
	if len(control.outline) != 1 {
		return nil, fmt.Errorf("Renovate control outline = %q, want one task item", control.outline)
	}
	return slices.Insert(template.outline, summary+1, control.outline...), nil
}

// TestRenovateTemplateLineBudget exercises the shipped-template input independently
// of the rendered body's existing limit.
func TestRenovateTemplateLineBudget(t *testing.T) {
	shipped := strings.TrimRight(readTemplate(t), "\n")
	padding := MaxPRLinesLimit - (strings.Count(shipped, "\n") + 1)
	if padding < 0 {
		t.Fatal("shipped template already exceeds the PR line limit")
	}
	atLimit := strings.Repeat("\n", padding) + shipped
	if _, err := renovateTemplateOutline(atLimit); err != nil {
		t.Fatalf("at line limit: %v", err)
	}
	if _, err := renovateTemplateOutline("\n" + atLimit); !errors.Is(err, util.ErrMarkedBlockBudget) {
		t.Fatalf("one line over: got %v, want line budget error", err)
	}
}

// TestRenovatePRBody checks the configured notes, summary fields, repository outline and receipt.
func TestRenovatePRBody(t *testing.T) {
	var config struct {
		Template string   `yaml:"prBodyTemplate"`
		Notes    []string `yaml:"prBodyNotes"`
	}
	decodeConsumer(t, filepath.Join(engineCheckout, "renovate.json"), &config)
	want, err := renovateTemplateOutline(readTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
	template, notes := config.Template, config.Notes
	moved := strings.Replace(template, renovateDefaultBody, "", 1)
	receiptHeading := want[len(want)-1]
	moved = strings.Replace(moved, receiptHeading, renovateDefaultBody+"\n\n"+receiptHeading, 1)
	checkRenovateReviewInputs(t, template, notes, want)
	checked := strings.Replace(template, "{{{controls}}}", "{{{controls}}}- [x] HISS-16 verified\n", 1)
	commented := strings.Replace(template, "{{{notes}}}", "<!-- {{{notes}}} -->", 1)
	checkRenderedRenovateMutations(t, checked, commented, notes, want)
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
		{"checked box after controls on the same line", checked, notes, false},
		{"asterisk checked box", "* [x] HISS-16 verified\n\n" + template, notes, false},
		{"unrelated ordered checked box", "1) [X] already reviewed\n\n" + template, notes, false},
		{"extra unchecked asterisk box", "* [ ] Extra item\n\n" + template, notes, false},
		{"commented notes", commented, notes, false},
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

// checkRenderedRenovateMutations exercises reader findings independently of the template comparison.
func checkRenderedRenovateMutations(t *testing.T, checked, commented string, notes, want []string) {
	t.Helper()
	err := checkRenovateOutline(renderRenovateBody(checked, notes), want)
	if err == nil || err.Error() != "rendered body contains a checked box" {
		t.Errorf("checked task after controls: %v", err)
	}
	for _, body := range []string{
		renderRenovateBody(commented, notes),
		renovateSummary + "\n\n<!-- closed --> <!--\n\n" + renovateNote + "\n\n-->",
	} {
		if err := checkRenovateNote(body); err == nil || err.Error() != "rendered summary is missing the visible takeover note" {
			t.Errorf("hidden takeover note: %v", err)
		}
	}
}

// TestRenovateOutlineEmptyBody retains the validator's finding alongside its call error.
func TestRenovateOutlineEmptyBody(t *testing.T) {
	err := checkRenovateOutline(" \n", nil)
	if err == nil || !strings.Contains(err.Error(), "empty PR body") || !strings.Contains(err.Error(), "PR body is empty; checklist required") {
		t.Fatalf("expected both the call error and the finding: %v", err)
	}
}

// checkRenovateReviewInputs pins the reason each altered template fails the normal body check.
func checkRenovateReviewInputs(t *testing.T, template string, notes, want []string) {
	t.Helper()
	receiptHeading := want[len(want)-1]
	lines := strings.Split(template, "\n")
	firstBox := slices.IndexFunc(lines, func(line string) bool { return strings.HasPrefix(line, "- [ ] **HISS-01 ") })
	if firstBox < 0 {
		t.Fatal("shipped pull request template is missing the HISS-01 task item")
	}
	hiddenBox := strings.Replace(template, lines[firstBox], "<!--\n"+lines[firstBox]+"\n-->", 1)
	conditional := "{{#if false}}\n" + strings.Replace(template, receiptHeading, "{{/if}}\n"+receiptHeading, 1)
	for _, tc := range []struct{ name, template, finding string }{
		{"multiline comment hides HISS-01", hiddenBox, "rendered outline"},
		{"conditional hides everything before section 4", conditional, "unexpected Handlebars expression"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRenovateBody(tc.template, notes, want)
			if err == nil || !strings.Contains(err.Error(), tc.finding) {
				t.Fatalf("got %v, want %q", err, tc.finding)
			}
		})
	}
	for _, directive := range []string{"{{/if}}", "{{else}}", "{{^notes}}", "{{! comment}}", "{{header}}", "{{> partial}}", "{{~notes~}}"} {
		t.Run(directive, func(t *testing.T) {
			if err := checkRenovateBody(directive+"\n"+template, notes, want); err == nil {
				t.Fatalf("accepted surplus Handlebars expression %q", directive)
			}
		})
	}
}
