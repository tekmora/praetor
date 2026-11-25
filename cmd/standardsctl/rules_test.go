package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/forge"
	"github.com/cordanaLLM/praetor/internal/util"
)

// TestRulesAuditCLI_ReportsProseOnlyWithoutFailing verifies guidance status, enforced explanation, and JSON output.
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
	const guidanceRow = "\nHISS-01 guidance status=guidance prose-only\n"
	guide, err := contextopt.ReadSnapshot(t.Context(), filepath.Join("..", "..", "docs", "guides", "adoption-verification.md"))
	if err != nil {
		t.Fatal(err)
	}
	guideText, _ := util.NormalizeLineEndings(string(guide))
	mustContain(t, guideText, guidanceRow)
	mustContain(t, out, guidanceRow,
		"AGENTS-OP-1 guidance status=guidance prose-only",
		"statuses: present=0, forge-observed=0, forge-pending=0, unresolved=0, guidance=22",
		"enforced: 0 (live forge read-back matched with no pending forge setting; local pointer presence is status=present, not enforced)",
		"instruction-only prohibitions:", "  AGENTS-OP-1", "unenforced: 22")
	jsonOut, err := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"audit", "--root=" + root, "--json"})
	})
	if err != nil || !strings.Contains(jsonOut, "\"status\": \"guidance\"") || !strings.Contains(jsonOut, "\"prose_only\": true") {
		t.Fatalf("rules audit JSON = (%q, %v)", jsonOut, err)
	}
	mustContain(t, jsonOut, `"enforced": false`)
	helpOut, helpErr := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"--help"})
	})
	if helpErr != nil || !strings.Contains(helpOut, "local pointer resolution reports status=present, not enforced") {
		t.Fatalf("rules --help = (%q, %v)", helpOut, helpErr)
	}
	if err := dispatchCommand("rules", []string{"unknown"}); err == nil {
		t.Fatal("unknown rules subcommand succeeded")
	}
}

// TestRulesAuditCLI_TextWriteError requires the command to return the stdout write failure.
func TestRulesAuditCLI_TextWriteError(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "AGENTS.md", "## Operational Rules\n\n1. Check.\n\n## Text Register\n")
	writeFixtureFile(t, root, ".config/rules/enforcement.yaml", "version: 1\nrules: []\n")
	out, err := os.Open(filepath.Join(root, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = out
	t.Cleanup(func() {
		os.Stdout = stdout
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	})
	err = dispatchCommand("rules", []string{"audit", "--root", root})
	var writeErr *os.PathError
	if !errors.As(err, &writeErr) || writeErr.Op != "write" || writeErr.Path != out.Name() {
		t.Fatalf("rules audit error = %v, want write error for %s", err, out.Name())
	}
}

// TestRulesAuditCLI_FailsOnUnresolvedPointer verifies missing and empty pointers report status=unresolved and fail.
func TestRulesAuditCLI_FailsOnUnresolvedPointer(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "AGENTS.md", "## Operational Rules\n\n1. Check.\n\n## Text Register\n")
	writeFixtureFile(t, root, "Makefile", "empty:\n")
	writeFixtureFile(t, root, ".config/rules/enforcement.yaml", "version: 1\nrules:\n  - id: HISS-01\n    class: ci-gate\n    evidence: [make:empty]\n")
	out, err := captureStdout(t, func() error {
		return dispatchCommand("rules", []string{"audit", "--root", root})
	})
	if err == nil {
		t.Fatal("rules audit error = nil, want failure on unresolved empty Make target")
	}
	mustContain(t, out, "HISS-01 ci-gate status=unresolved unresolved: make:empty")
}

// TestRulesAuditCLI_ForgeReadbackPositiveAndOffline verifies present vs forge-pending vs forge-observed in CLI and JSON.
func TestRulesAuditCLI_ForgeReadbackPositiveAndOffline(t *testing.T) {
	f := rulesAuditForgeFixture(t)
	reader := &rulesProtectionStub{live: rulesLiveProtection("CI")}
	offline, err := captureStdout(t, func() error {
		return runRulesAuditWithReader([]string{"--root", f.dir}, reader)
	})
	if err != nil || reader.calls != 0 {
		t.Fatalf("offline rules audit = (%v, calls=%d)\n%s", err, reader.calls, offline)
	}
	mustContain(t, offline,
		"HISS-01 ci-gate status=forge-pending asserted, not read back",
		"AGENTS-OP-1 ci-gate status=present resolved",
		"asserted, not read back:", "HISS-01 forge:required_checks asserted 1",
		"statuses: present=1, forge-observed=0, forge-pending=1, unresolved=0, guidance=20",
		"enforced: 0 (live forge read-back matched with no pending forge setting; local pointer presence is status=present, not enforced)",
		"unenforced: 22")

	remoteText, err := captureStdout(t, func() error {
		return runRulesAuditWithReader([]string{"--root", f.dir, "--remote"}, reader)
	})
	if err != nil || reader.calls != 1 {
		t.Fatalf("remote text rules audit = (%v, calls=%d)\n%s", err, reader.calls, remoteText)
	}
	mustContain(t, remoteText,
		"HISS-01 ci-gate status=forge-observed resolved",
		"AGENTS-OP-1 ci-gate status=present resolved",
		"statuses: present=1, forge-observed=1, forge-pending=0, unresolved=0, guidance=20",
		"enforced: 1", "unenforced: 21")

	remote, err := captureStdout(t, func() error {
		return runRulesAuditWithReader([]string{"--root", f.dir, "--remote", "--json"}, reader)
	})
	if err != nil || reader.calls != 2 {
		t.Fatalf("remote rules audit = (%v, calls=%d)\n%s", err, reader.calls, remote)
	}
	mustContain(t, remote, `"status": "forge-observed"`, `"status": "present"`,
		`"asserted": "1"`, `"observed": "1 of 1 required"`,
		`"match": true`, `"read_back": true`, `"enforced": true`)
}

// TestRulesAuditCLI_ForgeReadbackNegativeAndError verifies live forge drift and readback errors fail closed.
func TestRulesAuditCLI_ForgeReadbackNegativeAndError(t *testing.T) {
	f := rulesAuditForgeFixture(t)
	drift := &rulesProtectionStub{live: rulesLiveProtection()}
	out, err := captureStdout(t, func() error {
		return runRulesAuditWithReader([]string{"--root", f.dir, "--remote"}, drift)
	})
	if err == nil || drift.calls != 1 {
		t.Fatalf("drift rules audit = (%v, calls=%d)\n%s", err, drift.calls, out)
	}
	mustContain(t, out,
		"HISS-01 ci-gate status=unresolved unresolved",
		"HISS-01 forge:required_checks asserted 1, observed 0 of 1 required; missing: CI, match=false",
		"invalid: HISS-01: forge setting required_checks mismatch: asserted 1, observed 0 of 1 required; missing: CI")

	unread := &rulesProtectionStub{err: errors.New("read refused")}
	out, err = captureStdout(t, func() error {
		return runRulesAuditWithReader([]string{"--root", f.dir, "--remote"}, unread)
	})
	if err == nil || unread.calls != 1 {
		t.Fatalf("unread rules audit = (%v, calls=%d)\n%s", err, unread.calls, out)
	}
	mustContain(t, out, "invalid: forge readback failed: read the live branch protection of main: read refused")
}

// rulesAuditForgeFixture builds a protected repository fixture declaring one forge pointer and one workflow pointer.
func rulesAuditForgeFixture(t *testing.T) *auditFixture {
	t.Helper()
	f := protectedFixture(t, false, "", &forgeStub{})
	agents := "## Operational Rules\n\n1. The agent is told not to bypass checks.\n\n## Text Register\n"
	writeFixtureFile(t, f.dir, "AGENTS.md", agents)
	writeFixtureFile(t, f.dir, ".config/rules/enforcement.yaml", "version: 1\nrules:\n"+
		"  - id: HISS-01\n    class: ci-gate\n    evidence: [forge:required_checks]\n"+
		"  - id: AGENTS-OP-1\n    class: ci-gate\n    evidence: [workflow:ci.yml#ci]\n")
	return f
}

type rulesProtectionStub struct {
	live  *forge.LiveBranchProtection
	err   error
	calls int
}

// ReadBranchProtection returns the stub's configured live protection state and error.
func (s *rulesProtectionStub) ReadBranchProtection(_ context.Context, _ string) (*forge.LiveBranchProtection, error) {
	s.calls++
	return s.live, s.err
}

// rulesLiveProtection builds a legacy branch-protection snapshot requiring the given status check contexts.
func rulesLiveProtection(checks ...string) *forge.LiveBranchProtection {
	return &forge.LiveBranchProtection{Branch: "main", Legacy: &forge.LegacyBranchProtection{
		RequiredStatusChecks: &forge.LegacyStatusChecks{Contexts: checks},
	}}
}
