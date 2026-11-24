package dedupe

import (
	"strings"
	"testing"
)

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

// TestForeignDuplicateVerdictSuffix_Boundary_ExactThreeGroups checks that exactly three groups
// within the per-group location cap render in full with no omitted-count text.
func TestForeignDuplicateVerdictSuffix_Boundary_ExactThreeGroups(t *testing.T) {
	locs := make([]FileLocation, 0, maxForeignVerdictLocations)
	for j := 0; j < maxForeignVerdictLocations; j++ {
		locs = append(locs, FileLocation{Path: "a.py", Line: j*10 + 1, EndLine: j*10 + 5})
	}
	groups := []DuplicateGroup{
		{Language: "python", Locations: locs},
		{Language: "rust", Locations: []FileLocation{{Path: "b.rs", Line: 1, EndLine: 6}, {Path: "c.rs", Line: 1, EndLine: 6}}},
		{Language: "yaml", Locations: []FileLocation{{Path: "ci.yml", Line: 10, EndLine: 20}, {Path: "cd.yml", Line: 10, EndLine: 20}}},
	}
	got := ForeignDuplicateVerdictSuffix(groups)
	for _, want := range []string{"python: a.py:1-5", "a.py:51-55", "; rust: b.rs:1-6, c.rs:1-6", "; yaml: ci.yml:10-20, cd.yml:10-20)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("got %q, want substring %q", got, want)
		}
	}
	if strings.Contains(got, "more") || strings.Contains(got, "locations") {
		t.Fatalf("exact boundary must omit overflow suffixes, got %q", got)
	}
}

// TestForeignDuplicateVerdictSuffix_Boundary_CapsGroupsAndLocations checks the four-group and
// eight-location overflow cases, including both omitted-count annotations.
func TestForeignDuplicateVerdictSuffix_Boundary_CapsGroupsAndLocations(t *testing.T) {
	groups := make([]DuplicateGroup, 0, 4)
	langs := []string{"python", "rust", "yaml", "lua"}
	for i := 0; i < 4; i++ {
		locs := make([]FileLocation, 0, maxForeignVerdictLocations+2)
		for j := 0; j < maxForeignVerdictLocations+2; j++ {
			locs = append(locs, FileLocation{Path: "f.py", Line: j + 1, EndLine: j + 2})
		}
		groups = append(groups, DuplicateGroup{Language: langs[i], Locations: locs})
	}
	got := ForeignDuplicateVerdictSuffix(groups)
	if !strings.Contains(got, "; …+1 more)") {
		t.Fatalf("got %q, want omitted group count '; …+1 more)'", got)
	}
	if !strings.Contains(got, ", …+2 locations") {
		t.Fatalf("got %q, want omitted location count ', …+2 locations'", got)
	}
	if strings.Contains(got, "lua:") || strings.Contains(got, "f.py:7-8") {
		t.Fatalf("fourth group and seventh location must be omitted, got %q", got)
	}
}
