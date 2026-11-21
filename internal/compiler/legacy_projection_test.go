// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

package compiler

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/agentcontext"
)

var legacyProjectionFixtures = [...]struct {
	rel     string
	fixture string
	legacy  bool
}{
	{rel: "CLAUDE.md", fixture: "claude.txt", legacy: true},
	{rel: ".cursor/rules/hiss-invariants.mdc", fixture: "cursor.txt", legacy: true},
	{rel: ".github/copilot-instructions.md", fixture: "copilot.txt", legacy: false},
	{rel: ".windsurfrules", fixture: "windsurf.txt", legacy: true},
	{rel: ".gemini/GEMINI.md", fixture: "gemini.txt", legacy: true},
	{rel: ".codex/rules.md", fixture: "codex.txt", legacy: true},
}

// stageLegacyProjectionFixture populates a temporary repository with the checked-in 3c01c322c outputs.
func stageLegacyProjectionFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join("testdata", "legacy-projections")
	source := filepath.Join(root, "AGENTS.md")
	writeCanonicalFixture(t, source, readFixtureText(t, filepath.Join(base, "agents.txt")))
	writeOutputFixture(t, filepath.Join(root, ReadOnlyFile), readFixtureText(t, filepath.Join(base, "readonly.txt")))
	writeOutputFixture(t, filepath.Join(root, "docs", "extra.md"), "- Extra imported rule.\n")
	for _, item := range legacyProjectionFixtures {
		body := readFixtureText(t, filepath.Join(base, item.fixture))
		writeOutputFixture(t, filepath.Join(root, filepath.FromSlash(item.rel)), body)
	}
	return root, source
}

// transpilerAtClock binds a Transpiler to a deterministic clock reading.
func transpilerAtClock(now time.Time) *Transpiler {
	tr := NewTranspiler()
	tr.Env = &agentcontext.RenderEnv{Now: func() time.Time { return now }}
	return tr
}

// TestVerifyCompiledContext_LegacyProjectionWindow_Positive accepts exact 3c01c322c outputs with expiry warnings.
func TestVerifyCompiledContext_LegacyProjectionWindow_Positive(t *testing.T) {
	clocks := []time.Time{
		time.Date(2026, 11, 21, 18, 10, 0, 0, time.UTC),
		time.Date(2026, 12, 1, 23, 59, 59, 0, time.UTC),
	}
	for _, now := range clocks {
		root, source := stageLegacyProjectionFixture(t)
		var out bytes.Buffer
		err := VerifyCompiledContext(t.Context(), &out, transpilerAtClock(now), source, root)
		if err != nil {
			t.Fatalf("at %s: verify rejected 3c01c322c fixtures: %v\n%s", now.Format(time.RFC3339), err, out.String())
		}
		assertLegacyProjectionWarnings(t, out.String())
	}
}

// assertLegacyProjectionWarnings checks that each changed target warns once with 2026-12-01 and Copilot does not.
func assertLegacyProjectionWarnings(t *testing.T, rendered string) {
	t.Helper()
	for _, item := range legacyProjectionFixtures {
		want := item.rel + " is in the previous full-content form; run 'praetorctl compile-context' before 2026-12-01 (legacy projection window)"
		count := strings.Count(rendered, want)
		if item.legacy && count != 1 {
			t.Errorf("%s: warning count = %d, want 1 in:\n%s", item.rel, count, rendered)
		}
		if !item.legacy && count != 0 {
			t.Errorf("%s: unexpected legacy warning in:\n%s", item.rel, rendered)
		}
	}
}

// TestVerifyCompiledContext_LegacyProjectionWindow_PointerPassesWithoutWarning writes pointers and warns nothing.
func TestVerifyCompiledContext_LegacyProjectionWindow_PointerPassesWithoutWarning(t *testing.T) {
	root, source := stageLegacyProjectionFixture(t)
	now := time.Date(2026, 11, 21, 18, 10, 0, 0, time.UTC)
	var compileOut bytes.Buffer
	if err := CompileContextProjections(t.Context(), &compileOut, transpilerAtClock(now), source, root); err != nil {
		t.Fatalf("compile-context write: %v", err)
	}
	claude := readFixtureText(t, filepath.Join(root, "CLAUDE.md"))
	if !strings.Contains(claude, "@AGENTS.md") || strings.Contains(claude, "Verify state before edit") {
		t.Fatalf("compile-context wrote non-pointer CLAUDE.md:\n%s", claude)
	}
	var verifyOut bytes.Buffer
	if err := VerifyCompiledContext(t.Context(), &verifyOut, transpilerAtClock(now), source, root); err != nil {
		t.Fatalf("verify pointer outputs: %v\n%s", err, verifyOut.String())
	}
	if strings.Contains(verifyOut.String(), "legacy projection window") || strings.Contains(verifyOut.String(), "previous full-content form") {
		t.Fatalf("pointer projections emitted legacy warning:\n%s", verifyOut.String())
	}
}

// TestVerifyCompiledContext_LegacyProjectionWindow_Negative_EditedOrStaleOldFormFails rejects edited or stale copies.
func TestVerifyCompiledContext_LegacyProjectionWindow_Negative_EditedOrStaleOldFormFails(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 10, 0, 0, time.UTC)

	root, source := stageLegacyProjectionFixture(t)
	claudePath := filepath.Join(root, "CLAUDE.md")
	editedClaude := strings.Replace(readFixtureText(t, claudePath), "- Claude client rule.", "- Hand-edited client rule.", 1)
	writeOutputFixture(t, claudePath, editedClaude)
	var out bytes.Buffer
	err := VerifyCompiledContext(t.Context(), &out, transpilerAtClock(now), source, root)
	if err == nil || !strings.Contains(err.Error(), "target CLAUDE.md is out of sync") {
		t.Fatalf("edited legacy CLAUDE.md: got %v, want out-of-sync error", err)
	}

	staleRoot, staleSource := stageLegacyProjectionFixture(t)
	updatedAgents := strings.Replace(readFixtureText(t, staleSource), "- Run targeted package tests.", "- Run updated package checks.", 1)
	writeCanonicalFixture(t, staleSource, updatedAgents)
	ro, roErr := agentcontext.ReadOnlyTarget(updatedAgents)
	if roErr != nil {
		t.Fatal(roErr)
	}
	writeOutputFixture(t, filepath.Join(staleRoot, ReadOnlyFile), ro.Content)
	out.Reset()
	err = VerifyCompiledContext(t.Context(), &out, transpilerAtClock(now), staleSource, staleRoot)
	if err == nil {
		t.Fatal("projections from older AGENTS.md accepted")
	}
	for _, item := range legacyProjectionFixtures {
		if !strings.Contains(err.Error(), "target "+item.rel+" is out of sync") {
			t.Errorf("stale %s not reported out of sync: %v", item.rel, err)
		}
	}
}

// TestVerifyCompiledContext_LegacyProjectionWindow_Negative_ExpiredWindowFails rejects 3c01c322c outputs after 2026-12-01.
func TestVerifyCompiledContext_LegacyProjectionWindow_Negative_ExpiredWindowFails(t *testing.T) {
	root, source := stageLegacyProjectionFixture(t)
	afterExpiry := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	err := VerifyCompiledContext(t.Context(), &out, transpilerAtClock(afterExpiry), source, root)
	if err == nil {
		t.Fatal("expired legacy projection window accepted previous full-content form")
	}
	for _, item := range legacyProjectionFixtures {
		got := strings.Contains(err.Error(), "target "+item.rel+" is out of sync")
		if got != item.legacy {
			t.Errorf("after expiry %s out-of-sync=%v, want %v (err=%v)", item.rel, got, item.legacy, err)
		}
	}
	if strings.Contains(out.String(), "legacy projection window") {
		t.Fatalf("expired window printed legacy warning:\n%s", out.String())
	}
}
