package dedupe

import (
	"fmt"
	"strings"
)

const (
	maxForeignVerdictGroups    = 3
	maxForeignVerdictLocations = 6
)

// FormatFileLocation returns path:line or path:line-endline for a clone location.
func FormatFileLocation(loc FileLocation) string {
	location := fmt.Sprintf("%s:%d", loc.Path, loc.Line)
	if loc.EndLine > loc.Line && loc.EndLine != 0 {
		location += fmt.Sprintf("-%d", loc.EndLine)
	}
	return location
}

// ForeignDuplicateVerdictSuffix names up to maxForeignVerdictGroups foreign clone groups with file spans.
func ForeignDuplicateVerdictSuffix(groups []DuplicateGroup) string {
	if len(groups) == 0 {
		return ""
	}
	limit := len(groups)
	if limit > maxForeignVerdictGroups {
		limit = maxForeignVerdictGroups
	}
	var b strings.Builder
	b.WriteString(" (")
	for i := 0; i < limit; i++ {
		if i > 0 {
			b.WriteString("; ")
		}
		g := groups[i]
		b.WriteString(g.Language)
		b.WriteString(": ")
		locLimit := len(g.Locations)
		if locLimit > maxForeignVerdictLocations {
			locLimit = maxForeignVerdictLocations
		}
		for j := 0; j < locLimit; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(FormatFileLocation(g.Locations[j]))
		}
		if len(g.Locations) > locLimit {
			fmt.Fprintf(&b, ", …+%d locations", len(g.Locations)-locLimit)
		}
	}
	if len(groups) > limit {
		fmt.Fprintf(&b, "; …+%d more", len(groups)-limit)
	}
	b.WriteString(")")
	return b.String()
}
