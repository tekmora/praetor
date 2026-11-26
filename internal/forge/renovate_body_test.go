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

// renovateBodyOutline collects visible headings and checkbox lines verbatim, in order.
// An empty receipt-labelled fence is still a receipt prompt on a bot pull request.
func renovateBodyOutline(body string) (lines []string, receiptFence bool) {
	var fence util.MarkdownFence
	for line := range strings.SplitSeq(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		wasOpen := fence.Open()
		if fence.Inside(strings.TrimSpace(line)) {
			if !wasOpen && isReceiptFence(line) {
				receiptFence = true
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "- [") {
			lines = append(lines, line)
		}
	}
	return lines, receiptFence
}

// renovateBodyParts lists Renovate's fields in their default rendering order.
var renovateBodyParts = [...]string{"header", "table", "warnings", "notes", "changelogs", "configDescription", "controls", "footer"}

const renovateControl = "- [ ] <!-- rebase-check --> If you want to rebase/retry this PR, check this box"

// renderRenovateBody requires each field exactly once in the summary and expands it with sample Markdown.
func renderRenovateBody(template string, notes []string) (string, error) {
	beforeRule, _, hasRule := strings.Cut(template, "\n---\n")
	_, summary, hasSummary := strings.Cut(beforeRule, "\n## Summary of Changes\n")
	if !hasRule || !hasSummary {
		return "", fmt.Errorf("expected Summary of Changes before the first section rule")
	}
	summary, _, _ = strings.Cut(summary, "\n## ")
	body := template
	for _, part := range renovateBodyParts {
		token := "{{{" + part + "}}}"
		_, rest, found := strings.Cut(summary, token)
		if !found || strings.Count(template, token) != 1 {
			return "", fmt.Errorf("expected one %s in Summary of Changes in Renovate's default order", token)
		}
		summary = rest
		sample := "Sample " + part + "\n"
		switch part {
		case "notes":
			sample = strings.Join(notes, "\n\n") + "\n"
		case "controls":
			sample = "\n\n" + renovateControl + "\n\n"
		}
		body = strings.Replace(body, token, sample, 1)
	}
	return body, nil
}

// checkRenovateBody checks repository-owned outline lines and the receipt section as rendered.
func checkRenovateBody(template string, notes, wantOutline []string) error {
	const note = "Record any remaining CodeRabbit Description warning on the takeover pull request."
	if !slices.Equal(notes, []string{note}) {
		return fmt.Errorf("prBodyNotes = %q, want only %q", notes, note)
	}
	body, err := renderRenovateBody(template, notes)
	if err != nil {
		return err
	}
	// Only literal template lines belong to the repository checklist. Renovate supplies its own controls.
	got, _ := renovateBodyOutline(template)
	if !slices.Equal(got, wantOutline) {
		return fmt.Errorf("template outline = %q, want %q", got, wantOutline)
	}
	if _, fence := renovateBodyOutline(body); fence {
		return fmt.Errorf("rendered body contains a receipt fence")
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
	if len(want) == 0 {
		t.Fatal("shipped pull request template has no headings or checkboxes")
	}
	template, notes := config.Template, config.Notes
	t.Run("rendered controls checkbox", func(t *testing.T) {
		body, err := renderRenovateBody(template, notes)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(strings.Split(body, "\n"), renovateControl) {
			t.Error("rendered controls must include the rebase/retry checkbox on its own line")
		}
	})
	defaultBody := "{{{" + strings.Join(renovateBodyParts[:], "}}}{{{") + "}}}"
	moved := template
	for _, part := range renovateBodyParts {
		moved = strings.Replace(moved, "{{{"+part+"}}}", "", 1)
	}
	receiptHeading := want[len(want)-1]
	moved = strings.Replace(moved, receiptHeading, defaultBody+"\n\n"+receiptHeading, 1)
	for _, tc := range []struct {
		name, template string
		notes          []string
		valid          bool
	}{
		{"configured body with controls checkbox", template, notes, true},
		{"empty notes", template, []string{}, false},
		{"changed takeover note", template, []string{"Record the warning."}, false},
		{"additional note", template, append(slices.Clone(notes), "Another note."), false},
		{"default body without template sections", defaultBody, notes, false},
		{"parts moved before section 4", moved, notes, false},
		{"missing controls", strings.Replace(template, "{{{controls}}}", "", 1), notes, false},
		{"checked box", strings.Replace(template, "- [ ]", "- [x]", 1), notes, false},
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
