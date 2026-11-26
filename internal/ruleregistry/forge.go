package ruleregistry

import (
	"context"
	"fmt"
	"strings"
)

// ForgeSetting is one branch-protection property the live forge read exposes.
type ForgeSetting string

const (
	ForgeRequiredSignatures ForgeSetting = "required_signatures"
	ForgeLinearHistory      ForgeSetting = "linear_history"
	ForgeRequiredReviews    ForgeSetting = "required_reviews"
	ForgeRequiredChecks     ForgeSetting = "required_checks"
)

// ForgeState is the canonical branch-protection comparison for one setting.
type ForgeState struct {
	Asserted         string
	Observed         string
	Match            bool
	ReadBack         bool
	AssertedEnforced bool
}

// ForgeComparison is the asserted and observed evidence attached to one rule.
type ForgeComparison struct {
	Setting  ForgeSetting `json:"setting"`
	Asserted string       `json:"asserted"`
	Observed string       `json:"observed,omitempty"`
	Match    bool         `json:"match"`
	ReadBack bool         `json:"read_back"`
}

// ForgeProvider resolves committed assertions and, for remote audits, their live readback.
type ForgeProvider func(context.Context) (map[ForgeSetting]ForgeState, error)

// AuditOptions supplies evidence that cannot be resolved from the repository alone.
type AuditOptions struct {
	Forge ForgeProvider
}

func forgeSetting(pointer string) (ForgeSetting, bool) {
	kind, value, ok := strings.Cut(pointer, ":")
	if !ok || kind != "forge" {
		return "", false
	}
	setting := ForgeSetting(value)
	return setting, validForgeSetting(setting)
}

func validForgeSetting(setting ForgeSetting) bool {
	switch setting {
	case ForgeRequiredSignatures, ForgeLinearHistory, ForgeRequiredReviews, ForgeRequiredChecks:
		return true
	default:
		return false
	}
}

// registryNeedsForge reports whether any rule within the audit bounds declares a forge setting pointer, so the forge is read only when evidence needs it.
func registryNeedsForge(registry *Registry) bool {
	for i := 0; i < len(registry.Rules) && i < maxAuditRules; i++ {
		pointers := registry.Rules[i].Evidence
		if len(pointers) > maxEvidencePointers {
			continue
		}
		for j := 0; j < len(pointers) && j < maxEvidencePointers; j++ {
			if _, ok := forgeSetting(pointers[j]); ok {
				return true
			}
		}
	}
	return false
}

// loadForgeStates collects valid settings and retains any provider error with the audit diagnostics.
func loadForgeStates(
	ctx context.Context,
	registry *Registry,
	opts AuditOptions,
	report *auditDiagnostics,
) map[ForgeSetting]ForgeState {
	states := map[ForgeSetting]ForgeState{}
	if !registryNeedsForge(registry) {
		return states
	}
	if opts.Forge == nil {
		report.Problems = append(report.Problems, "forge evidence provider is required")
		return states
	}
	resolved, err := opts.Forge(ctx)
	if err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("forge readback failed: %v", err))
		report.causes = append(report.causes, err)
	}
	for setting, state := range resolved {
		if validForgeSetting(setting) {
			states[setting] = state
		}
	}
	return states
}
