// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hisscatalog

import (
	slashpath "path"

	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/util"
)

// ScannerLanguage is a bitset of source and configuration languages the internal/hiss static
// scanner decides for one HISS invariant. Bits keep Rule a value type that Rules and LookupRule
// copy without aliasing.
type ScannerLanguage uint16

const (
	// ScanGo is Go source (.go).
	ScanGo ScannerLanguage = 1 << iota
	// ScanC is native C, C++, Objective-C++, CUDA and HIP source (hiss.IsNativeExtension).
	ScanC
	// ScanRust is Rust source (.rs).
	ScanRust
	// ScanPython is Python source (.py).
	ScanPython
	// ScanJavaScript is JavaScript source (.js, .jsx, .mjs, .cjs).
	ScanJavaScript
	// ScanTypeScript is TypeScript source (.ts, .tsx, .mts, .cts).
	ScanTypeScript
	// ScanSvelte is Svelte component source (.svelte).
	ScanSvelte
	// ScanShell is POSIX shell and Bash scripts (.sh, .bash and extensionless scripts).
	ScanShell
	// ScanGitHubActions is GitHub Actions workflow documents (.github/workflows/*.yml|*.yaml).
	ScanGitHubActions
	// ScanSystemd is systemd unit files (.service, .socket).
	ScanSystemd
	// ScanAnsible is Ansible playbooks and role task YAML files (.yml, .yaml).
	ScanAnsible

	scanScript = ScanJavaScript | ScanTypeScript | ScanSvelte
	scanCode   = ScanGo | ScanC | ScanRust | ScanPython | scanScript | ScanShell | ScanGitHubActions
)

// sourceLanguageBits maps source and content scanner language names to catalog bits.
var sourceLanguageBits = map[string]ScannerLanguage{
	"go":             ScanGo,
	"rust":           ScanRust,
	"python":         ScanPython,
	"javascript":     ScanJavaScript,
	"typescript":     ScanTypeScript,
	"svelte":         ScanSvelte,
	"shell":          ScanShell,
	"github-actions": ScanGitHubActions,
	"systemd":        ScanSystemd,
	"ansible":        ScanAnsible,
}

// ScannerLanguageForPath resolves a target using its extension or the supplied content
// scanner decision. Validation supplies candidates and an audit supplies the scan's claims.
func ScannerLanguageForPath(rel string, contentLanguage func(string) string) ScannerLanguage {
	rel = util.NormalizeSlashes(rel)
	if rel == "" {
		return 0
	}
	if hiss.IsNativeExtension(slashpath.Ext(rel)) {
		return ScanC
	}
	if lang := sourceLanguageBits[util.SourceLanguage(rel)]; lang != 0 {
		return lang
	}
	return sourceLanguageBits[contentLanguage(rel)]
}

// ScannerDecidesLanguage reports whether the internal/hiss scanner decides r for lang.
func (r Rule) ScannerDecidesLanguage(lang ScannerLanguage) bool {
	return lang != 0 && r.Scanner&lang != 0
}

// ScannerDecidesPath reports whether the internal/hiss scanner decides r for rel.
func (r Rule) ScannerDecidesPath(rel string, contentLanguage func(string) string) bool {
	return r.ScannerDecidesLanguage(ScannerLanguageForPath(rel, contentLanguage))
}

// ScannerDecides reports whether id is a catalog invariant whose internal/hiss scanner cell
// covers rel.
func ScannerDecides(id, rel string, contentLanguage func(string) string) bool {
	rule, ok := LookupRule(id)
	return ok && rule.ScannerDecidesPath(rel, contentLanguage)
}

// IsScannerRule reports whether the internal/hiss scanner decides id in at least one language.
func IsScannerRule(id string) bool {
	rule, ok := LookupRule(id)
	return ok && rule.Scanner != 0
}
