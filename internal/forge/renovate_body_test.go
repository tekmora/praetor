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

// renderRenovateBody substitutes sample Markdown and repository notes in Renovate's field order.
func renderRenovateBody(template string, notes []string) (string, error) {
	parts := [...]string{"header", "table", "warnings", "notes", "changelogs", "configDescription", "controls", "footer"}
	if template == "" {
		// The baseline has no override, so Renovate concatenates the eight fields.
		template = "{{{" + strings.Join(parts[:], "}}}{{{") + "}}}"
	}
	var body strings.Builder
	rest := template
	for _, part := range parts {
		token := "{{{" + part + "}}}"
		before, after, found := strings.Cut(rest, token)
		if !found || strings.Count(template, token) != 1 {
			return "", fmt.Errorf("expected one %s in Renovate's default order", token)
		}
		body.WriteString(before)
		if part == "notes" {
			body.WriteString(strings.Join(notes, "\n\n"))
		} else {
			body.WriteString("Sample " + part)
		}
		body.WriteString("\n\n")
		rest = after
	}
	body.WriteString(rest)
	return body.String(), nil
}

// TestRenovatePRBody renders renovate.json's prBodyTemplate and notes and checks the body's headings and
// checkboxes against the repository PR template, that it has no receipt fence, and that its receipt
// section holds the takeover sentence.
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
	body, err := renderRenovateBody(config.Template, config.Notes)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := renderRenovateBody("", nil)
	if err != nil {
		t.Fatal(err)
	}
	const receipt = "The takeover pull request for `fix/renovate-<number>` carries the signed receipt."
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"configured body", body, true},
		{"default body without template sections", baseline, false},
		{"checked box", strings.Replace(body, "- [ ]", "- [x]", 1), false},
		{"empty receipt fence", "~~~receipt\n~~~\n\n" + body, false},
		{"placeholder after receipt note", body + "\n{}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, fence := renovateBodyOutline(tc.body)
			_, section, found := strings.Cut(tc.body, want[len(want)-1]+"\n")
			valid := slices.Equal(got, want) && !fence && found && strings.TrimSpace(section) == receipt
			if valid != tc.valid {
				t.Errorf("outline = %q, want %q; receipt fence = %t, receipt section = %q", got, want, fence, section)
			}
		})
	}
}

// TestRenovatePRBodyMissingControls refuses a body template that drops Renovate's own controls part.
func TestRenovatePRBodyMissingControls(t *testing.T) {
	if _, err := renderRenovateBody("{{{header}}}{{{table}}}{{{warnings}}}{{{notes}}}{{{changelogs}}}{{{configDescription}}}{{{footer}}}", nil); err == nil {
		t.Fatal("body template missing Renovate's controls was accepted")
	}
}
