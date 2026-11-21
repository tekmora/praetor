// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

package agentcontext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/tools/secrets/rules"
)

// TestLegacyProjectionWindow_3D checks MEL category C expiry bounds and clock evaluation.
func TestLegacyProjectionWindow_3D(t *testing.T) {
	entered := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if prob := rules.CategoryExpiryProblem(LegacyProjectionCategory, LegacyProjectionEntered, LegacyProjectionExpires, entered); prob != "" {
		t.Fatalf("legacy projection window violates MEL category C: %s", prob)
	}
	if LegacyProjectionExpired(entered) {
		t.Fatal("window expired on entered date")
	}
	boundary := time.Date(2026, 12, 1, 23, 59, 59, 0, time.UTC)
	if LegacyProjectionExpired(boundary) {
		t.Fatal("window expired before end of expires date")
	}
	after := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
	if !LegacyProjectionExpired(after) {
		t.Fatal("window remained active after expires date")
	}
}

// TestCompileLegacyContent_Projection_3D checks byte identity with 3c01c322c fixtures and refusals.
func TestCompileLegacyContent_Projection_3D(t *testing.T) {
	base := filepath.Join("..", "compiler", "testdata", "legacy-projections")
	agentsBytes, err := os.ReadFile(filepath.Join(base, "agents.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewTranspiler().CompileLegacyContent(string(agentsBytes))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]string{
		"CLAUDE.md":                         "claude.txt",
		".cursor/rules/hiss-invariants.mdc": "cursor.txt",
		".github/copilot-instructions.md":   "copilot.txt",
		".windsurfrules":                    "windsurf.txt",
		".gemini/GEMINI.md":                 "gemini.txt",
		".codex/rules.md":                   "codex.txt",
	}
	for rel, name := range fixtures {
		wantBytes, readErr := os.ReadFile(filepath.Join(base, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got[rel] != string(wantBytes) {
			t.Errorf("%s legacy output differs from 3c01c322c fixture", rel)
		}
	}
	requireCompileLegacyContentRefusals(t)
}

// requireCompileLegacyContentRefusals covers empty canonical text, unknown client selection, and line budget overflow.
func requireCompileLegacyContentRefusals(t *testing.T) {
	t.Helper()
	if _, err := NewTranspiler().CompileLegacyContent("   \n"); err == nil {
		t.Fatal("empty canonical content accepted")
	}
	badClient := NewTranspiler()
	badClient.Clients = []string{"unknown-client"}
	if _, err := badClient.CompileLegacyContent("# Policy\n"); err == nil {
		t.Fatal("unknown client accepted")
	}
	tight := NewTranspiler()
	tight.MaxLines = 2
	if _, err := tight.CompileLegacyContent("# Policy\n- Line.\n"); err == nil || !strings.Contains(err.Error(), "max line budget") {
		t.Fatalf("over-budget legacy target accepted: %v", err)
	}
}
