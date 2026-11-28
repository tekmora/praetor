// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestGatePolicy_Constant_MaxDeclaredVerifyTimeout(t *testing.T) {
	if got := MaxDeclaredVerifyTimeout; got != 30*time.Minute {
		t.Fatalf("MaxDeclaredVerifyTimeout = %v, want 30m", got)
	}
}

func TestGatePolicy_Positive_DeclaredVerifyTimeout(t *testing.T) {
	manifest, err := ParseManifest("test", []byte(`version: 1
gate:
  declared_verify_timeout: 20m
`))
	if err != nil {
		t.Fatalf("expected valid manifest, got: %v", err)
	}
	if manifest.Gate == nil {
		t.Fatal("expected manifest.Gate to be populated")
	}
	if got := manifest.Gate.DeclaredVerifyTimeoutDuration(); got != 20*time.Minute {
		t.Errorf("DeclaredVerifyTimeoutDuration() = %v, want 20m", got)
	}
}

func TestGatePolicy_Negative_DeclaredVerifyTimeoutRefused(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		wantErr  string
		wantSubs []string
	}{
		{
			name: "above ceiling 31m",
			yaml: `version: 1
gate:
  declared_verify_timeout: 31m
`,
			wantSubs: []string{"gate.declared_verify_timeout", "31m", "ceiling", "30m0s"},
		},
		{
			name: "not positive 0s",
			yaml: `version: 1
gate:
  declared_verify_timeout: 0s
`,
			wantSubs: []string{"gate.declared_verify_timeout", "0s", "ceiling", "30m0s"},
		},
		{
			name: "not positive negative duration",
			yaml: `version: 1
gate:
  declared_verify_timeout: -5m
`,
			wantSubs: []string{"gate.declared_verify_timeout", "-5m", "ceiling", "30m0s"},
		},
		{
			name: "invalid duration string",
			yaml: `version: 1
gate:
  declared_verify_timeout: not-a-duration
`,
			wantSubs: []string{"gate.declared_verify_timeout", "not-a-duration", "ceiling"},
		},
		{
			name: "unknown key",
			yaml: `version: 1
gate:
  unknown_key: 10m
`,
			wantSubs: []string{"gate", "unknown_key"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifest("test", []byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			msg := err.Error()
			for _, sub := range tc.wantSubs {
				if !strings.Contains(msg, sub) {
					t.Errorf("error %q does not contain expected substring %q", msg, sub)
				}
			}
		})
	}
}

func TestGatePolicy_Boundary_CeilingAndOmitted(t *testing.T) {
	exactCeiling, err := ParseManifest("test", []byte(`version: 1
gate:
  declared_verify_timeout: 30m
`))
	if err != nil {
		t.Fatalf("exact ceiling 30m must be accepted: %v", err)
	}
	if got := exactCeiling.Gate.DeclaredVerifyTimeoutDuration(); got != 30*time.Minute {
		t.Errorf("DeclaredVerifyTimeoutDuration() = %v, want 30m", got)
	}

	oneNano, err := ParseManifest("test", []byte(`version: 1
gate:
  declared_verify_timeout: 1ns
`))
	if err != nil {
		t.Fatalf("smallest positive 1ns must be accepted: %v", err)
	}
	if got := oneNano.Gate.DeclaredVerifyTimeoutDuration(); got != time.Nanosecond {
		t.Errorf("DeclaredVerifyTimeoutDuration() = %v, want 1ns", got)
	}

	omitted, err := ParseManifest("test", []byte(`version: 1`))
	if err != nil {
		t.Fatalf("omitted gate section must be accepted: %v", err)
	}
	if got := omitted.Gate.DeclaredVerifyTimeoutDuration(); got != 0 {
		t.Errorf("omitted gate section duration = %v, want 0", got)
	}
	if omitted.Gate.EnforceReadmePresentation() {
		t.Error("omitted gate section must not enforce README presentation by default")
	}

	enforced, err := ParseManifest("test", []byte("version: 1\ngate:\n  readme_presentation: true\n"))
	if err != nil {
		t.Fatalf("gate.readme_presentation must be accepted: %v", err)
	}
	if !enforced.Gate.EnforceReadmePresentation() {
		t.Error("expected EnforceReadmePresentation() == true")
	}
}

func TestGatePolicy_ReadmePresentationEnforced(t *testing.T) {
	dir := t.TempDir()
	if got, err := ReadmePresentationEnforced(dir); err != nil || got {
		t.Fatalf("absent manifest: got=(%v, %v), want (false, nil)", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".standards.yaml"), []byte("version: 1\ngate:\n  readme_presentation: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadmePresentationEnforced(dir); err != nil || !got {
		t.Fatalf("enforced manifest: got=(%v, %v), want (true, nil)", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".standards.yaml"), []byte("version: 1\ngate:\n  unknown_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadmePresentationEnforced(dir); err == nil || got {
		t.Fatalf("invalid manifest: got=(%v, %v), want (false, non-nil error)", got, err)
	}
}

// roundTripGateArgv renders manifest back to YAML and extracts test_prepare and test_wrapper.
func roundTripGateArgv(t *testing.T, manifest *Manifest) ([][]string, []string) {
	t.Helper()
	rendered, err := RenderManifest(manifest)
	if err != nil {
		t.Fatalf("RenderManifest: %v", err)
	}
	var doc struct {
		Gate struct {
			TestPrepare [][]string `yaml:"test_prepare"`
			TestWrapper []string   `yaml:"test_wrapper"`
		} `yaml:"gate"`
	}
	if err := yaml.Unmarshal(rendered, &doc); err != nil {
		t.Fatalf("unmarshal rendered manifest: %v", err)
	}
	return doc.Gate.TestPrepare, doc.Gate.TestWrapper
}

// TestGatePolicy_Positive_TestPrepareAndWrapper verifies gate.test_prepare and gate.test_wrapper
// load from .standards.yaml and preserve multi-word argv strings without shell splitting.
func TestGatePolicy_Positive_TestPrepareAndWrapper(t *testing.T) {
	body := `version: 1
gate:
  declared_verify_timeout: 15m
  readme_presentation: true
  test_wrapper:
    - "xvfb-run"
    - "-a"
    - "-s"
    - "-screen 0 1280x1024x24"
  test_prepare:
    - ["zig", "build", "-Doptimize=ReleaseSafe"]
    - ["zig", "build", "headers"]
`
	path := filepath.Join(t.TempDir(), ".standards.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid test_prepare and test_wrapper: %v", err)
	}
	prepare, wrapper := roundTripGateArgv(t, manifest)
	wantWrapper := []string{"xvfb-run", "-a", "-s", "-screen 0 1280x1024x24"}
	if !slices.Equal(wrapper, wantWrapper) {
		t.Fatalf("test_wrapper = %q, want %q", wrapper, wantWrapper)
	}
	if len(prepare) != 2 || !slices.Equal(prepare[0], []string{"zig", "build", "-Doptimize=ReleaseSafe"}) ||
		!slices.Equal(prepare[1], []string{"zig", "build", "headers"}) {
		t.Fatalf("test_prepare = %q, want two zig argv lists", prepare)
	}
}

// malformedGateCase describes one invalid gate section and the substrings its error must name.
type malformedGateCase struct {
	name     string
	yaml     string
	wantSubs []string
}

// buildRepeatedYAMLList builds a YAML flow list of count quoted items for bound tests.
func buildRepeatedYAMLList(item string, count int) string {
	const limit = 64
	parts := make([]string, 0, count)
	for i := 0; i < count && i < limit; i++ {
		parts = append(parts, item)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// malformedGateCases returns the negative cases for gate.test_prepare, gate.test_wrapper, and gateKeys.
func malformedGateCases() []malformedGateCase {
	overCmds := buildRepeatedYAMLList(`["zig", "build"]`, 17)
	overArgs := buildRepeatedYAMLList(`"arg"`, 33)
	overBytes := `"` + strings.Repeat("a", 1025) + `"`
	return []malformedGateCase{
		{"prepare scalar string", "version: 1\ngate:\n  test_prepare: \"zig build\"\n", []string{"gate.test_prepare", "[0]"}},
		{"prepare empty command list", "version: 1\ngate:\n  test_prepare: []\n", []string{"gate.test_prepare", "[0]"}},
		{"prepare empty first argv", "version: 1\ngate:\n  test_prepare: [[]]\n", []string{"gate.test_prepare", "[0]"}},
		{"prepare empty second argv", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\"]\n    - []\n", []string{"gate.test_prepare", "[1]"}},
		{"prepare inner string not list", "version: 1\ngate:\n  test_prepare: [\"zig build\"]\n", []string{"gate.test_prepare", "[0]"}},
		{"prepare non-string int", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\", 123]\n", []string{"gate.test_prepare", "[0][1]"}},
		{"prepare non-string bool", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\"]\n    - [true]\n", []string{"gate.test_prepare", "[1][0]"}},
		{"prepare empty arg string", "version: 1\ngate:\n  test_prepare:\n    - [\"\"]\n", []string{"gate.test_prepare", "[0][0]"}},
		{"prepare blank arg string", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\", \"   \"]\n", []string{"gate.test_prepare", "[0][1]"}},
		{"prepare control char", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\", \"a\\nb\"]\n", []string{"gate.test_prepare", "[0][1]"}},
		{"prepare over command bound", "version: 1\ngate:\n  test_prepare: " + overCmds + "\n", []string{"gate.test_prepare", "[16]"}},
		{"prepare over arg bound", "version: 1\ngate:\n  test_prepare: [" + overArgs + "]\n", []string{"gate.test_prepare", "[0][32]"}},
		{"prepare over byte bound", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\", " + overBytes + "]\n", []string{"gate.test_prepare", "[0][1]"}},
		{"wrapper scalar string", "version: 1\ngate:\n  test_wrapper: \"xvfb-run -a\"\n", []string{"gate.test_wrapper", "[0]"}},
		{"wrapper empty argv", "version: 1\ngate:\n  test_wrapper: []\n", []string{"gate.test_wrapper", "[0]"}},
		{"wrapper non-string int", "version: 1\ngate:\n  test_wrapper: [\"xvfb-run\", 99]\n", []string{"gate.test_wrapper", "[1]"}},
		{"wrapper empty arg string", "version: 1\ngate:\n  test_wrapper: [\"\"]\n", []string{"gate.test_wrapper", "[0]"}},
		{"wrapper over arg bound", "version: 1\ngate:\n  test_wrapper: " + overArgs + "\n", []string{"gate.test_wrapper", "[32]"}},
		{"unknown key beside test_prepare", "version: 1\ngate:\n  test_prepare:\n    - [\"zig\", \"build\"]\n  test_shell: true\n", []string{"gate", "test_shell"}},
	}
}

// TestGatePolicy_Negative_MalformedTestPrepareAndWrapper verifies malformed values fail LoadManifest
// naming the offending key and index.
func TestGatePolicy_Negative_MalformedTestPrepareAndWrapper(t *testing.T) {
	if _, err := ParseManifest("baseline", []byte("version: 1\ngate:\n  test_prepare:\n    - [\"zig\", \"build\"]\n")); err != nil {
		t.Fatalf("valid gate.test_prepare baseline must parse first: %v", err)
	}
	cases := malformedGateCases()
	for i := 0; i < len(cases) && i < 32; i++ {
		tc := cases[i]
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".standards.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			assertErrorSubstrings(t, err.Error(), tc.wantSubs)
		})
	}
}

// assertErrorSubstrings fails t when msg lacks any expected substring.
func assertErrorSubstrings(t *testing.T, msg string, wantSubs []string) {
	t.Helper()
	for i := 0; i < len(wantSubs) && i < 8; i++ {
		if !strings.Contains(msg, wantSubs[i]) {
			t.Errorf("error %q does not contain %q", msg, wantSubs[i])
		}
	}
}

// TestGatePolicy_Boundary_TestPrepareAndWrapperLimits checks exact command, argument, and byte ceilings
// as well as an empty gate mapping.
func TestGatePolicy_Boundary_TestPrepareAndWrapperLimits(t *testing.T) {
	exactCmds := buildRepeatedYAMLList(`["zig"]`, 16)
	exactArgs := buildRepeatedYAMLList(fmt.Sprintf("%q", "x"), 32)
	exactBytes := fmt.Sprintf("%q", strings.Repeat("b", 1024))
	body := fmt.Sprintf("version: 1\ngate:\n  test_prepare: %s\n  test_wrapper: %s\n", exactCmds, exactArgs)
	manifest, err := ParseManifest("ceiling", []byte(body))
	if err != nil {
		t.Fatalf("exact command/arg ceilings must be accepted: %v", err)
	}
	prepare, wrapper := roundTripGateArgv(t, manifest)
	if len(prepare) != 16 || len(wrapper) != 32 {
		t.Fatalf("got (%d commands, %d wrapper args), want (16, 32)", len(prepare), len(wrapper))
	}
	byteBody := fmt.Sprintf("version: 1\ngate:\n  test_prepare:\n    - [\"zig\", %s]\n  test_wrapper: [%s]\n", exactBytes, exactBytes)
	if _, err := ParseManifest("byte-ceiling", []byte(byteBody)); err != nil {
		t.Fatalf("exact 1024-byte arguments must be accepted: %v", err)
	}
	emptyGate, err := ParseManifest("empty-gate", []byte("version: 1\ngate: {}\n"))
	if err != nil {
		t.Fatalf("empty gate mapping must be accepted: %v", err)
	}
	emptyPrep, emptyWrap := roundTripGateArgv(t, emptyGate)
	if len(emptyPrep) != 0 || len(emptyWrap) != 0 {
		t.Errorf("empty gate mapping decoded prepare=%v wrapper=%v, want empty", emptyPrep, emptyWrap)
	}
}
