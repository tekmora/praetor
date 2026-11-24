// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hisscatalog

import (
	slashpath "path"
	"strings"

	"github.com/cordanaLLM/praetor/internal/ghworkflow"
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

// sourceLanguageBits maps util.SourceLanguage names to their ScannerLanguage bit.
var sourceLanguageBits = map[string]ScannerLanguage{
	"go":         ScanGo,
	"rust":       ScanRust,
	"python":     ScanPython,
	"javascript": ScanJavaScript,
	"typescript": ScanTypeScript,
	"svelte":     ScanSvelte,
	"shell":      ScanShell,
}

// ScannerLanguageForPath maps a repository-relative path or glob target to the language scanner
// internal/hiss dispatches for it, or 0 when no HISS language scanner owns it.
func ScannerLanguageForPath(rel string) ScannerLanguage {
	slashRel := strings.TrimSpace(util.NormalizeSlashes(rel))
	if slashRel == "" {
		return 0
	}
	if ghworkflow.IsWorkflowPath(slashRel) {
		return ScanGitHubActions
	}
	_, name := slashpath.Split(slashRel)
	ext := strings.ToLower(slashpath.Ext(name))
	if hiss.IsNativeExtension(ext) {
		return ScanC
	}
	if lang, ok := specialScannerLanguage(name, ext); ok {
		return lang
	}
	return sourceLanguageBits[util.SourceLanguage(name)]
}

// specialScannerLanguage classifies content-claimed extensions and extensionless shell targets.
func specialScannerLanguage(name, ext string) (ScannerLanguage, bool) {
	switch ext {
	case ".service", ".socket":
		return ScanSystemd, true
	case ".yml", ".yaml":
		return ScanAnsible, true
	case "":
		if name != "" && !strings.ContainsAny(name, "*?[") {
			return ScanShell, true
		}
	}
	return 0, false
}

// ScannerDecidesLanguage reports whether the internal/hiss scanner decides r for lang.
func (r Rule) ScannerDecidesLanguage(lang ScannerLanguage) bool {
	return lang != 0 && r.Scanner&lang != 0
}

// ScannerDecidesPath reports whether the internal/hiss scanner decides r for rel.
func (r Rule) ScannerDecidesPath(rel string) bool {
	return r.ScannerDecidesLanguage(ScannerLanguageForPath(rel))
}

// ScannerDecides reports whether id is a catalog invariant whose internal/hiss scanner cell
// covers rel.
func ScannerDecides(id, rel string) bool {
	rule, ok := LookupRule(id)
	return ok && rule.ScannerDecidesPath(rel)
}

// IsScannerRule reports whether the internal/hiss scanner decides id in at least one language.
func IsScannerRule(id string) bool {
	rule, ok := LookupRule(id)
	return ok && rule.Scanner != 0
}
