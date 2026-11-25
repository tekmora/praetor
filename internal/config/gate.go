// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// MaxDeclaredVerifyTimeout is the maximum duration gate.declared_verify_timeout may declare (30 min).
// It also sets the ceiling for the race-detector test stage timeout (gating.MaxTestStageTimeout).
const MaxDeclaredVerifyTimeout = 30 * time.Minute

// Bounds of the gate section's test preparation and wrapper argv lists (HISS-02).
const (
	// MaxGateTestPrepareCommands bounds how many commands gate.test_prepare may declare.
	MaxGateTestPrepareCommands = 16
	// MaxGateTestCommandArgs bounds how many words one gate.test_prepare command or gate.test_wrapper may carry.
	MaxGateTestCommandArgs = 32
	// MaxGateTestArgBytes bounds the byte length of one word in gate.test_prepare or gate.test_wrapper.
	MaxGateTestArgBytes = 1024
)

// GatePolicy is the manifest's gate section: settings of the anti-direct-merge gating pipeline.
// declared_verify_timeout sets the stage bound for the declared-verification stage.
// readme_presentation turns measured-not-enforced README presentation report lines into an
// enforced gate failure when no baseline entry covers the findings.
// test_prepare lists argv commands run in order in the isolated test worktree before the Cargo
// and Go test suites; test_wrapper prefixes one argv list to each prepare command and each test
// suite command. It is repository-only, like Documentation and Security, and stays out of ResolvedPolicy.
type GatePolicy struct {
	DeclaredVerifyTimeout string     `yaml:"declared_verify_timeout,omitempty"`
	ReadmePresentation    bool       `yaml:"readme_presentation,omitempty"`
	TestPrepare           [][]string `yaml:"test_prepare,omitempty"`
	TestWrapper           []string   `yaml:"test_wrapper,omitempty"`
	hasTestPrepare        bool
	hasTestWrapper        bool
}

// gateKeys is the closed key set of the gate section.
var gateKeys = []string{"declared_verify_timeout", "readme_presentation", "test_prepare", "test_wrapper"}

// EnforceReadmePresentation reports whether the manifest enforces the README presentation gate.
func (p *GatePolicy) EnforceReadmePresentation() bool {
	return p != nil && p.ReadmePresentation
}

// PrepareCommands returns a deep copy of the declared gate.test_prepare argv lists, or nil when unset.
func (p *GatePolicy) PrepareCommands() [][]string {
	if p == nil || len(p.TestPrepare) == 0 {
		return nil
	}
	out := make([][]string, 0, len(p.TestPrepare))
	for i := 0; i < len(p.TestPrepare) && i < MaxGateTestPrepareCommands; i++ {
		out = append(out, slices.Clone(p.TestPrepare[i]))
	}
	return out
}

// WrapperCommand returns a copy of the declared gate.test_wrapper argv list, or nil when unset.
func (p *GatePolicy) WrapperCommand() []string {
	if p == nil || len(p.TestWrapper) == 0 {
		return nil
	}
	return slices.Clone(p.TestWrapper)
}

// ReadmePresentationEnforced reports whether the manifest at root declares gate.readme_presentation: true.
// An absent manifest returns false, nil (report-only default); an unreadable or invalid manifest returns an error.
func ReadmePresentationEnforced(root string) (bool, error) {
	m, err := LoadManifest(filepath.Join(root, ".standards.yaml"))
	if errors.Is(err, os.ErrNotExist) || (err == nil && m == nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.Gate.EnforceReadmePresentation(), nil
}

// UnmarshalYAML checks that all keys are known and decodes GatePolicy with strict argv lists.
func (p *GatePolicy) UnmarshalYAML(node *yaml.Node) error {
	if err := requireKnownKeys(node, "gate", gateKeys); err != nil {
		return err
	}
	type rawGateScalars struct {
		DeclaredVerifyTimeout string `yaml:"declared_verify_timeout,omitempty"`
		ReadmePresentation    bool   `yaml:"readme_presentation,omitempty"`
	}
	var scalars rawGateScalars
	if err := node.Decode(&scalars); err != nil {
		return err
	}
	prepare, hasPrepare, err := decodeGateTestPrepareField(node)
	if err != nil {
		return err
	}
	wrapper, hasWrapper, err := decodeGateTestWrapperField(node)
	if err != nil {
		return err
	}
	*p = GatePolicy{
		DeclaredVerifyTimeout: scalars.DeclaredVerifyTimeout,
		ReadmePresentation:    scalars.ReadmePresentation,
		TestPrepare:           prepare,
		TestWrapper:           wrapper,
		hasTestPrepare:        hasPrepare,
		hasTestWrapper:        hasWrapper,
	}
	return nil
}

// decodeGateTestPrepareField decodes gate.test_prepare when present on a gate mapping node.
func decodeGateTestPrepareField(node *yaml.Node) ([][]string, bool, error) {
	prepNode := policyMember(node, "test_prepare")
	if prepNode == nil {
		return nil, false, nil
	}
	if prepNode.Kind != yaml.SequenceNode {
		return nil, true, fmt.Errorf("gate.test_prepare[0]: expected a non-empty list of argv lists")
	}
	if len(prepNode.Content) == 0 {
		return nil, true, fmt.Errorf("gate.test_prepare[0]: command list must not be empty")
	}
	if len(prepNode.Content) > MaxGateTestPrepareCommands {
		return nil, true, fmt.Errorf("gate.test_prepare[%d]: lists %d commands; maximum is %d",
			MaxGateTestPrepareCommands, len(prepNode.Content), MaxGateTestPrepareCommands)
	}
	cmds := make([][]string, 0, len(prepNode.Content))
	for i := 0; i < len(prepNode.Content) && i < MaxGateTestPrepareCommands; i++ {
		argv, err := decodeGateArgvNode(prepNode.Content[i], fmt.Sprintf("gate.test_prepare[%d]", i), false)
		if err != nil {
			return nil, true, err
		}
		cmds = append(cmds, argv)
	}
	return cmds, true, nil
}

// decodeGateTestWrapperField decodes gate.test_wrapper when present on a gate mapping node.
func decodeGateTestWrapperField(node *yaml.Node) ([]string, bool, error) {
	wrapNode := policyMember(node, "test_wrapper")
	if wrapNode == nil {
		return nil, false, nil
	}
	argv, err := decodeGateArgvNode(wrapNode, "gate.test_wrapper", true)
	if err != nil {
		return nil, true, err
	}
	return argv, true, nil
}

// decodeGateArgvNode decodes one YAML sequence node as a bounded, non-empty string argv list.
func decodeGateArgvNode(node *yaml.Node, key string, indexOnSeq bool) ([]string, error) {
	seqKey := key
	if indexOnSeq {
		seqKey = key + "[0]"
	}
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s: expected a non-empty argv list of strings", seqKey)
	}
	if len(node.Content) == 0 {
		return nil, fmt.Errorf("%s: argv must not be empty", seqKey)
	}
	if len(node.Content) > MaxGateTestCommandArgs {
		return nil, fmt.Errorf("%s[%d]: has %d arguments; maximum is %d",
			key, MaxGateTestCommandArgs, len(node.Content), MaxGateTestCommandArgs)
	}
	argv := make([]string, 0, len(node.Content))
	for j := 0; j < len(node.Content) && j < MaxGateTestCommandArgs; j++ {
		val, err := decodeGateArgScalar(node.Content[j], fmt.Sprintf("%s[%d]", key, j))
		if err != nil {
			return nil, err
		}
		argv = append(argv, val)
	}
	return argv, nil
}

// decodeGateArgScalar decodes a single YAML scalar node as a validated non-empty argv string.
func decodeGateArgScalar(node *yaml.Node, elemKey string) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("%s: argument must be a string", elemKey)
	}
	if err := validateGateArg(elemKey, node.Value); err != nil {
		return "", err
	}
	return node.Value, nil
}

// DeclaredVerifyTimeoutDuration returns the declared verify-all timeout as a time.Duration,
// or 0 if unset. ValidateGate has already verified that if set, it is positive and <= MaxDeclaredVerifyTimeout.
func (p *GatePolicy) DeclaredVerifyTimeoutDuration() time.Duration {
	if p == nil || p.DeclaredVerifyTimeout == "" {
		return 0
	}
	d, err := time.ParseDuration(p.DeclaredVerifyTimeout)
	if err != nil {
		return 0
	}
	return d
}

// validateManifestGate validates the gate section of the manifest: declared_verify_timeout,
// test_prepare, and test_wrapper.
func validateManifestGate(m *Manifest) error {
	if m == nil || m.Gate == nil {
		return nil
	}
	if err := validateDeclaredVerifyTimeout(m.Gate.DeclaredVerifyTimeout); err != nil {
		return err
	}
	if err := validateGateTestPrepare(m.Gate); err != nil {
		return err
	}
	return validateGateTestWrapper(m.Gate)
}

// validateDeclaredVerifyTimeout refuses a declared_verify_timeout above MaxDeclaredVerifyTimeout
// (30 min) or not positive, naming the key, value, and ceiling (no silent clamp).
func validateDeclaredVerifyTimeout(raw string) error {
	if raw == "" {
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("gate.declared_verify_timeout %q is not a duration (ceiling %s): %w",
			raw, MaxDeclaredVerifyTimeout, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("gate.declared_verify_timeout %s is not positive (ceiling %s)",
			raw, MaxDeclaredVerifyTimeout)
	}
	if parsed > MaxDeclaredVerifyTimeout {
		return fmt.Errorf("gate.declared_verify_timeout %s exceeds the %s ceiling",
			raw, MaxDeclaredVerifyTimeout)
	}
	return nil
}

// validateGateTestPrepare validates GatePolicy.TestPrepare when declared.
func validateGateTestPrepare(p *GatePolicy) error {
	if !p.hasTestPrepare && p.TestPrepare == nil {
		return nil
	}
	if len(p.TestPrepare) == 0 {
		return fmt.Errorf("gate.test_prepare[0]: command list must not be empty")
	}
	if len(p.TestPrepare) > MaxGateTestPrepareCommands {
		return fmt.Errorf("gate.test_prepare[%d]: lists %d commands; maximum is %d",
			MaxGateTestPrepareCommands, len(p.TestPrepare), MaxGateTestPrepareCommands)
	}
	for i := 0; i < len(p.TestPrepare) && i < MaxGateTestPrepareCommands; i++ {
		if err := validateGateArgv(fmt.Sprintf("gate.test_prepare[%d]", i), p.TestPrepare[i], false); err != nil {
			return err
		}
	}
	return nil
}

// validateGateTestWrapper validates GatePolicy.TestWrapper when declared.
func validateGateTestWrapper(p *GatePolicy) error {
	if !p.hasTestWrapper && p.TestWrapper == nil {
		return nil
	}
	return validateGateArgv("gate.test_wrapper", p.TestWrapper, true)
}

// validateGateArgv checks one argv slice against empty and length bounds and per-argument rules.
func validateGateArgv(key string, argv []string, indexOnSeq bool) error {
	if len(argv) == 0 {
		if indexOnSeq {
			return fmt.Errorf("%s[0]: argv must not be empty", key)
		}
		return fmt.Errorf("%s: argv must not be empty", key)
	}
	if len(argv) > MaxGateTestCommandArgs {
		return fmt.Errorf("%s[%d]: has %d arguments; maximum is %d",
			key, MaxGateTestCommandArgs, len(argv), MaxGateTestCommandArgs)
	}
	for j := 0; j < len(argv) && j < MaxGateTestCommandArgs; j++ {
		if err := validateGateArg(fmt.Sprintf("%s[%d]", key, j), argv[j]); err != nil {
			return err
		}
	}
	return nil
}

// validateGateArg refuses empty, whitespace-only, oversized, or control-character argv words.
func validateGateArg(elemKey, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("%s: argument must be a non-empty string", elemKey)
	}
	if len(val) > MaxGateTestArgBytes {
		return fmt.Errorf("%s: argument exceeds %d bytes", elemKey, MaxGateTestArgBytes)
	}
	if strings.ContainsFunc(val, unicode.IsControl) {
		return fmt.Errorf("%s: argument must not contain control characters", elemKey)
	}
	return nil
}
