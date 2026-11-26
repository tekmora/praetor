// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
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

// TestChecklistFirstReceiptInContainer rejects an invalid first receipt even with a valid second.
func TestChecklistFirstReceiptInContainer(t *testing.T) {
	first := "> ~~~receipt\n> invalid\n> ~~~\n"
	body := prChecklistBoxes + "\n" + first + fencedReceipt(t, "```receipt", "```")
	res, err := ValidatePRChecklist(body)
	if err != nil || res.Valid || res.HasReceipt || !containsFragment(res.Errors, "not valid receipt JSON") {
		t.Fatalf("expected the first receipt's JSON error: %+v, %v", res, err)
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
