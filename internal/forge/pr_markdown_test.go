// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestChecklistUsesOnlyVisibleTaskText distinguishes a real checked box from its hidden label.
func TestChecklistUsesOnlyVisibleTaskText(t *testing.T) {
	receipt := fencedReceipt(t, "```receipt", "```")
	for _, tc := range []struct{ name, label, visible string }{
		{"quoted comment", `Reviewed "<!-- HISS-16 -->"`, `Reviewed ""`},
		{"HTML attribute", `<span title="HISS-16">Reviewed</span>`, "Reviewed"},
		{"link destination", "[Reviewed](HISS-16)", "Reviewed"},
		{"autolink after hyphen", "HISS-<https://example.org>16", "HISS-https://example.org16"},
		{"autolink before hyphen", "HISS<https://example.org/>-16", "HISShttps://example.org/-16"},
		{"image alt text", "![HISS-16](https://example.org/badge.png)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "<!-- - [x] HISS-16 -->\n\n- [x] " + tc.label + "\n- [x] HISS-15\n" + receipt
			res, err := ValidatePRChecklist(body)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"- [x] " + tc.visible, "- [x] HISS-15"}
			if !slices.Equal(res.outline, want) {
				t.Errorf("visible checked items %q, want %q", res.outline, want)
			}
			if res.Valid || res.HasHISS16Check || !res.hasTickedBox || !res.Has3DTestsCheck || !res.HasReceipt {
				t.Fatalf("only the HISS-16 label is hidden: %+v", res)
			}
		})
	}
}

// TestChecklistMultilineCodeSpan keeps following tasks and a signed receipt visible.
func TestChecklistMultilineCodeSpan(t *testing.T) {
	body := "Example: `<!--\ncontinued`.\n\n" + prChecklistBoxes + fencedReceipt(t, "~~~json receipt", "~~~~")
	res, err := ValidatePRChecklist(body)
	if err != nil || !res.Valid || !res.HasHISS16Check || !res.Has3DTestsCheck || !res.HasReceipt {
		t.Fatalf("multiline code followed by a complete checklist: %+v, %v", res, err)
	}
}

// TestChecklistMarkdownOutline follows heading levels and visible labels in source order.
func TestChecklistMarkdownOutline(t *testing.T) {
	body := "Review <!-- hidden -->\n======\n\n- [X] `<!--\n  HISS-16`\n  - [ ] **pending**\n\n## Tests\n\n+ [x] 3D\n  tests"
	res, err := ValidatePRChecklist(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"# Review", "- [x] <!-- HISS-16", "- [ ] pending", "## Tests", "- [x] 3D\ntests"}
	if !slices.Equal(res.outline, want) || !res.HasHISS16Check || !res.Has3DTestsCheck {
		t.Fatalf("outline %q, want %q and both checks, got %+v", res.outline, want, res)
	}
}

// TestChecklistQuotedReceipts selects the first receipt outside a blockquote.
func TestChecklistQuotedReceipts(t *testing.T) {
	first := "> ~~~receipt\n> invalid\n> ~~~\n"
	signed := fencedReceipt(t, "```receipt", "```")
	body := prChecklistBoxes + "\n" + first + signed
	res, err := ValidatePRChecklist(body)
	if err != nil || !res.Valid || !res.HasReceipt {
		t.Fatalf("top-level signed receipt after quoted invalid JSON: %+v, %v", res, err)
	}
	quoted := "> " + strings.ReplaceAll(strings.TrimSpace(signed), "\n", "\n> ")
	res, err = ValidatePRChecklist("> - [x] HISS-16\n>\n" + quoted)
	if err != nil || res.HasReceipt || res.receiptFence || res.hasTickedBox {
		t.Fatalf("quoted task and signed receipt: %+v, %v", res, err)
	}
}

// TestChecklistCommentAcrossBlocks skips a second comment through its raw closer or EOF.
func TestChecklistCommentAcrossBlocks(t *testing.T) {
	hidden := "<!-- closed --> <!--\n\n- [x] HISS-16\n- [x] HISS-15\n\n" +
		fencedReceipt(t, "```receipt", "```")
	for _, tc := range []struct {
		name, suffix string
		want         []string
	}{
		{"visible after close", "\n<!-- close -->\n\n- [x] HISS-15", []string{"- [x] HISS-15"}},
		{"open at EOF", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidatePRChecklist(hidden + tc.suffix)
			if err != nil {
				t.Fatal(err)
			}
			if res.HasReceipt || res.receiptFence || res.HasHISS16Check || !slices.Equal(res.outline, tc.want) {
				t.Fatalf("expected only visible items %q: %+v", tc.want, res)
			}
			visible := len(tc.want) > 0
			if res.hasTickedBox != visible || res.Has3DTestsCheck != visible {
				t.Fatalf("expected visible HISS-15 task = %t: %+v", visible, res)
			}
		})
	}
}

// TestChecklistPartialCommentLabel keeps the visible prefix when the closer is in another block.
func TestChecklistPartialCommentLabel(t *testing.T) {
	body := "- [x] reviewed <!-- HISS-16\n\n-->\n\n- [x] HISS-15"
	res, err := ValidatePRChecklist(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"- [x] reviewed", "- [x] HISS-15"}
	if res.HasHISS16Check || !res.Has3DTestsCheck || !slices.Equal(res.outline, want) {
		t.Fatalf("expected visible task labels %q: %+v", want, res)
	}
}

// TestChecklistTextBesideImage preserves the visible label beside an image.
func TestChecklistTextBesideImage(t *testing.T) {
	res, err := ValidatePRChecklist("- [x] ![HISS-15](https://example.org/badge.png) HISS-16")
	if err != nil || !res.HasHISS16Check || res.Has3DTestsCheck || !slices.Equal(res.outline, []string{"- [x] HISS-16"}) {
		t.Fatalf("expected exactly the visible HISS-16 label: %+v, %v", res, err)
	}
}

// TestChecklistBodyLineBoundaries checks the complete signed body through the public validator.
func TestChecklistBodyLineBoundaries(t *testing.T) {
	body := strings.TrimSuffix(prChecklistBoxes+fencedReceipt(t, "```receipt", "```"), "\n")
	atLimit := strings.Repeat("\n", MaxPRLinesLimit-1-strings.Count(body, "\n")) + body
	for _, tc := range []struct{ name, body string }{
		{"CRLF", strings.ReplaceAll(body, "\n", "\r\n")},
		{"at line limit", atLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidatePRChecklist(tc.body)
			if err != nil || !res.Valid || !res.HasReceipt {
				t.Fatalf("complete body: %+v, %v", res, err)
			}
		})
	}
	res, err := ValidatePRChecklist("\n" + atLimit)
	if err != nil || res.Valid || res.HasReceipt || res.hasTickedBox || !containsFragment(res.Errors, "exceeds") {
		t.Fatalf("one line over must be rejected before parsing: %+v, %v", res, err)
	}
}

// TestChecklistBodyByteLimit reports a single finding before reading any checklist item.
func TestChecklistBodyByteLimit(t *testing.T) {
	const checked = "- [x] HISS-16\n"
	byteFinding := fmt.Sprintf("pull request body exceeds %d bytes", maxReferenceTextBytes)
	for _, tc := range []struct{ name, body, finding string }{
		{"oversized task", checked + strings.Repeat("x", maxReferenceTextBytes+1-len(checked)), byteFinding},
		{"oversized spaces", strings.Repeat(" ", maxReferenceTextBytes+1), byteFinding},
		{"oversized blank lines", strings.Repeat("\n", MaxPRLinesLimit), fmt.Sprintf("PR body exceeds %d lines", MaxPRLinesLimit)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidatePRChecklist(tc.body)
			if err != nil || res == nil {
				t.Fatalf("expected a checklist result for oversized input, got %+v, %v", res, err)
			}
			if res.Valid || res.HasHISS16Check || !slices.Equal(res.Errors, []string{tc.finding}) {
				t.Fatalf("expected only %q, got %+v", tc.finding, res)
			}
		})
	}
	body := prChecklistBoxes + fencedReceipt(t, "```receipt", "```") + "~~~\n"
	atLimit := body + strings.Repeat("x", maxReferenceTextBytes-len(body)-len("\n~~~")) + "\n~~~"
	res, err := ValidatePRChecklist(atLimit)
	if err != nil || !res.Valid {
		t.Fatalf("complete body at byte limit: %+v, %v", res, err)
	}
}

// TestChecklistSignedShippedTemplate fills the repository template as a contributor would.
func TestChecklistSignedShippedTemplate(t *testing.T) {
	prefix, rest, opened := strings.Cut(tickAll(readTemplate(t)), "```receipt\n")
	_, suffix, closed := strings.Cut(rest, "\n```\n")
	if !opened || !closed {
		t.Fatal("shipped template must provide a receipt fence")
	}
	res, err := ValidatePRChecklist(prefix + fencedReceipt(t, "```receipt", "```") + suffix)
	if err != nil || !res.Valid {
		t.Fatalf("filled shipped template: %+v, %v", res, err)
	}
}
