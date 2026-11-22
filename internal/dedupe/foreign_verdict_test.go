package dedupe

import "testing"

// TestFormatFileLocation_Positive_Span checks the path:start-end form for a location with an end line.
func TestFormatFileLocation_Positive_Span(t *testing.T) {
	got := FormatFileLocation(FileLocation{Path: "a.rs", Line: 3, EndLine: 9})
	if got != "a.rs:3-9" {
		t.Fatalf("got %q, want a.rs:3-9", got)
	}
}

// TestFormatFileLocation_Boundary_UnknownEnd checks the path:line form when the end line is unknown.
func TestFormatFileLocation_Boundary_UnknownEnd(t *testing.T) {
	got := FormatFileLocation(FileLocation{Path: "a.rs", Line: 3})
	if got != "a.rs:3" {
		t.Fatalf("got %q, want a.rs:3", got)
	}
}

// TestForeignDuplicateVerdictSuffix_Negative_Empty checks that no foreign groups give an empty verdict suffix.
func TestForeignDuplicateVerdictSuffix_Negative_Empty(t *testing.T) {
	if got := ForeignDuplicateVerdictSuffix(nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// TestForeignDuplicateVerdictSuffix_Positive_NamesGroups checks that the verdict suffix names each group's language and file spans.
func TestForeignDuplicateVerdictSuffix_Positive_NamesGroups(t *testing.T) {
	groups := []DuplicateGroup{{
		Language: "rust",
		Locations: []FileLocation{
			{Path: "src/a.rs", Line: 1, EndLine: 10},
			{Path: "src/b.rs", Line: 1, EndLine: 10},
		},
	}}
	got := ForeignDuplicateVerdictSuffix(groups)
	want := " (rust: src/a.rs:1-10, src/b.rs:1-10)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
