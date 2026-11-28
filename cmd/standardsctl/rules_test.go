package main

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestRulesAuditCLI_ReportsProseOnlyWithoutFailing(t *testing.T) {
	root := t.TempDir()
	agents := "## Operational Rules\n\n1. The agent is told not to bypass a check.\n\n## Text Register\n"
	writeFixtureFile(t, root, "AGENTS.md", agents)
	writeFixtureFile(t, root, ".config/rules/enforcement.yaml", "version: 1\nrules: []\n")
	out, err := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"audit", "--root", root})
	})
	if err != nil {
		t.Fatalf("rules audit error = %v", err)
	}
	mustContain(t, out, "HISS-01 guidance prose-only", "AGENTS-OP-1 guidance prose-only",
		"instruction-only prohibitions:", "  AGENTS-OP-1", "unenforced: 22")
	jsonOut, err := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"audit", "--root=" + root, "--json"})
	})
	if err != nil || !strings.Contains(jsonOut, "\"prose_only\": true") {
		t.Fatalf("rules audit JSON = (%q, %v)", jsonOut, err)
	}
	if err := dispatchCommand("rules", []string{"unknown"}); err == nil {
		t.Fatal("unknown rules subcommand succeeded")
	}
}

func TestRulesAuditCLI_FailsOnUnresolvedPointer(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "AGENTS.md", "## Operational Rules\n\n1. Check.\n\n## Text Register\n")
	writeFixtureFile(t, root, ".config/rules/enforcement.yaml", "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:absent]\n")
	_, err := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"audit", "--root", root})
	})
	if err == nil {
		t.Fatal("rules audit error = nil, want failure on unresolved evidence pointer")
	}
}

// TestRulesAuditCLI_ForgeReadbackPositiveAndOffline checks observed and local-only evidence.
func TestRulesAuditCLI_ForgeReadbackPositiveAndOffline(t *testing.T) {
	stub := &forgeStub{legacy: classicProtection("CI")}
	f := rulesAuditForgeFixture(t, stub)
	offline, err := captureStdout(t, func() error {
		return runRulesAudit([]string{"--root", f.dir})
	})
	if err != nil || stub.requestCount() != 0 {
		t.Fatalf("offline rules audit = (%v, calls=%d)\n%s", err, stub.requestCount(), offline)
	}
	mustContain(t, offline, "HISS-01 ci-gate asserted, not read back",
		"asserted, not read back:", "HISS-01 forge:required_checks asserted 1", "unenforced: 21")

	remote, err := captureStdout(t, func() error {
		return runRulesAudit([]string{"--root", f.dir, "--remote", "--token=fixture", "--endpoint=" + actionsForgeEndpoint, "--json"})
	})
	if err != nil {
		t.Fatalf("remote rules audit: %v\n%s", err, remote)
	}
	want := []string{"/repos/acme/widgets", forgeStubRepo + "rules/branches/main", forgeStubRepo + "rulesets", forgeStubRepo + "branches/main/protection"}
	if got := stub.readPaths(); !slices.Equal(got, want) {
		t.Fatalf("rules audit reads = %v, want %v", got, want)
	}
	mustContain(t, remote, `"asserted": "1"`, `"observed": "1 of 1 required"`,
		`"match": true`, `"read_back": true`, `"enforced": true`)
}

// TestRulesAuditCLI_TransferredRequiredCheck reports the guarded job missing from live protection.
func TestRulesAuditCLI_TransferredRequiredCheck(t *testing.T) {
	stub := &forgeStub{repo: transferredRepository(), legacy: classicProtection("CI")}
	f := rulesAuditForgeFixture(t, stub)
	writeFixtureFile(t, f.dir, ".github/workflows/transfer.yml", transferWorkflow())
	out, err := captureStdout(t, func() error {
		return runRulesAudit([]string{"--root", f.dir, "--remote", "--token=fixture", "--endpoint=" + actionsForgeEndpoint})
	})
	if err == nil {
		t.Fatalf("rules audit passed with Transfer gate missing:\n%s", out)
	}
	mustContain(t, out, "HISS-01 forge:required_checks asserted 2, observed 1 of 2 required; missing: Transfer gate, match=false")
	const base = "/repos/new-org/imago/"
	want := []string{"/repos/acme/widgets", base + "rules/branches/main", base + "rulesets", base + "branches/main/protection"}
	if got := stub.readPaths(); !slices.Equal(got, want) {
		t.Errorf("rules audit reads = %v, want %v", got, want)
	}
}

// TestRulesAuditCLI_ForgeReadbackNegativeAndError distinguishes drift from a failed read.
func TestRulesAuditCLI_ForgeReadbackNegativeAndError(t *testing.T) {
	f := rulesAuditForgeFixture(t, &forgeStub{legacy: classicProtection()})
	out, err := captureStdout(t, func() error {
		return runRulesAudit([]string{"--root", f.dir, "--remote", "--token=fixture", "--endpoint=" + actionsForgeEndpoint})
	})
	if err == nil {
		t.Fatalf("drift rules audit passed:\n%s", out)
	}
	mustContain(t, out, "HISS-01 forge:required_checks asserted 1, observed 0 of 1 required; missing: CI, match=false",
		"invalid: HISS-01: forge setting required_checks mismatch: asserted 1, observed 0 of 1 required; missing: CI")

	f = rulesAuditForgeFixture(t, &forgeStub{rulesStatus: http.StatusForbidden})
	out, err = captureStdout(t, func() error {
		return runRulesAudit([]string{"--root", f.dir, "--remote", "--token=fixture", "--endpoint=" + actionsForgeEndpoint})
	})
	if err == nil {
		t.Fatalf("unread rules audit passed:\n%s", out)
	}
	mustContain(t, out, "invalid: forge readback failed: read the live branch protection of main: read the active rules of main: unexpected status 403")
}

// rulesAuditForgeFixture declares required-check and workflow evidence for the supplied forge.
func rulesAuditForgeFixture(t *testing.T, stub *forgeStub) *auditFixture {
	t.Helper()
	f := protectedFixture(t, false, "", stub)
	agents := "## Operational Rules\n\n1. The agent is told not to bypass checks.\n\n## Text Register\n"
	writeFixtureFile(t, f.dir, "AGENTS.md", agents)
	writeFixtureFile(t, f.dir, ".config/rules/enforcement.yaml", "version: 1\nrules:\n"+
		"  - id: HISS-01\n    class: ci-gate\n    evidence: [forge:required_checks]\n"+
		"  - id: AGENTS-OP-1\n    class: ci-gate\n    evidence: [workflow:ci.yml#ci]\n")
	return f
}
