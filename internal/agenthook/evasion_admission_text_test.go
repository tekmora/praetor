// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/hiss"
)

// admissionExecutableText is the rule-masked command Python passes to heavy-step admission.
func admissionExecutableText(t *testing.T, command string) string {
	t.Helper()
	segments, err := commandSegments(command)
	if err != nil {
		t.Fatalf("commandSegments(%q): %v", command, err)
	}
	text := command
	if len(segments) > 0 && segments[0].raw != "" {
		text = segments[0].raw
	}
	return joinLineContinuations(text)
}

// TestEvasionQuotedCommitOptionAdmissionText proves admission-readable text for quoted commit options.
func TestEvasionQuotedCommitOptionAdmissionText(t *testing.T) {
	for _, command := range []string{
		`git commit "-m" "$message"`,
		`git commit '-m' "$message"`,
		`git commit -"m" docs`,
	} {
		t.Run(command, func(t *testing.T) {
			text := admissionExecutableText(t, command)
			if _, ok := hiss.ShellCode(text, admissionMaxLines); !ok {
				t.Fatalf("admission text unreadable: %q", text)
			}
		})
	}
}

// TestDataOffsetQuotedWholeOption checks raw-length masking for fully quoted commit options.
func TestDataOffsetQuotedWholeOption(t *testing.T) {
	const word = `"-m"`
	s := &shellSpans{gitCommand: "commit"}
	if offset := s.dataOffset(word); offset != len(word) {
		t.Fatalf("dataOffset(%q)=%d want raw length %d", word, offset, len(word))
	}
	s = &shellSpans{gitCommand: "commit"}
	if s.dataOffset(`"-mdocs"`) >= 0 {
		t.Fatal("attached quoted option value must stay refused")
	}
}

// TestDataOffsetQuotedWholeOptionMutant proves decoded-length masking leaves admission text unreadable.
func TestDataOffsetQuotedWholeOptionMutant(t *testing.T) {
	const command = `git commit "-m" "$message"`
	text := admissionExecutableText(t, command)
	decoded := len(shellDataOptionPattern.FindString(dataOptionWord(`"-m"`)))
	if decoded >= len(`"-m"`) {
		t.Fatal("mutant offset must be shorter than the raw option word")
	}
	quoted := strings.Index(command, `"-m"`)
	if quoted < 0 {
		t.Fatal("fixture command lacks quoted -m option")
	}
	mutant := []byte(text)
	for index := quoted + decoded; index < quoted+len(`"-m"`); index++ {
		mutant[index] = ' '
	}
	if _, ok := hiss.ShellCode(string(mutant), admissionMaxLines); ok {
		t.Fatal("decoded offset mask must leave admission text unreadable")
	}
}
