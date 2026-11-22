// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

package agentcontext

import (
	"fmt"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
	"github.com/cordanaLLM/praetor/tools/secrets/rules"
)

// Legacy full-content projection rollout window (order engine-pointer-projections-rollout-20261121):
// category C (10 days), entered 2026-11-21, expires 2026-12-01. Declared beside the renderer
// rather than in .standards.yaml exceptions because manifest exceptions bind one repository
// alone, whereas compile-context --verify checks un-recompiled adopter repositories before
// their manifests change.
const (
	LegacyProjectionEntered  = "2026-11-21"
	LegacyProjectionCategory = "C"
	LegacyProjectionExpires  = "2026-12-01"
)

// LegacyProjectionExpired reports whether the rollout window accepting previous full-content
// vendor projections has closed at now, under MEL exception day semantics (rules.Entry.Expired).
func LegacyProjectionExpired(now time.Time) bool {
	return (rules.Entry{
		Category: LegacyProjectionCategory,
		Entered:  LegacyProjectionEntered,
		Expires:  LegacyProjectionExpires,
	}).Expired(now)
}

// CompileLegacyContent renders the pre-pointer (3c01c322c) full-content form of each selected
// vendor target from canonical AGENTS.md content, keyed by relative target path. Verification
// calls it only when a target differs from the current pointer projection inside the window.
func (t *Transpiler) CompileLegacyContent(content string) (map[string]string, error) {
	targets, _, err := selectTargets(t.Clients)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("canonical AGENTS.md content is empty")
	}
	if lf, _, err := util.NormalizeLineEndingsStrict(content); err == nil {
		content = lf
	}
	lines, owners, err := ownVendorLines(content)
	if err != nil {
		return nil, err
	}
	bands, layered := scanBands(lines)
	out := make(map[string]string, len(targets))
	for _, target := range targets {
		body := renderVendorBody(lines, owners, bands, layered, target.section, true)
		text, err := renderLegacyTarget(target, body, t.MaxLines)
		if err != nil {
			return nil, err
		}
		out[target.path] = text
	}
	return out, nil
}

// renderLegacyTarget frames one pre-pointer full-content target with relative link and demand-import rewrites.
func renderLegacyTarget(target vendorTarget, body string, maxLines int) (string, error) {
	text := target.prefix + generatedHeader + body
	if depth := strings.Count(target.path, "/"); depth > 0 {
		text = rewriteRelativeLinks(text, depth)
	}
	importLines, imports, err := contextImports(text)
	if err != nil {
		return "", fmt.Errorf("target file %s: %w", target.path, err)
	}
	if target.importDepth == 0 {
		text = replaceDemandImports(importLines, imports)
	}
	if maxLines > 0 && countLines(text) > maxLines {
		return "", fmt.Errorf("target file %s exceeds max line budget (%d > %d)", target.path, countLines(text), maxLines)
	}
	return text, nil
}
