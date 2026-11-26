// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// recordRequest keeps all the fixture reads in wire order across both handlers.
func (s *actionsStub) recordRequest(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.EscapedPath())
}

// comparisonEndpoint serves both comparisons at an endpoint the remote flags can select.
func comparisonEndpoint(t *testing.T, actions *actionsStub, protection *forgeStub) string {
	t.Helper()
	rest := protection.handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widgets" || strings.Contains(r.URL.Path, "/actions/") {
			actions.serve(t, w, r)
			return
		}
		actions.recordRequest(r)
		rest(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// requireIdentityFirst checks the order of permission reads and rejects a second metadata GET.
func requireIdentityFirst(t *testing.T, got []string) {
	t.Helper()
	want := []string{
		"GET /repos/acme/widgets",
		"GET /repos/acme/widgets/actions/permissions/workflow",
		"GET /orgs/acme/actions/permissions/workflow",
	}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) || slices.Contains(got[len(want):], want[0]) {
		t.Fatalf("requests = %v, want %v first with one repository GET", got, want)
	}
}

// TestPlanRemoteIdentityFirst uses only the explicit connection for both live comparisons.
func TestPlanRemoteIdentityFirst(t *testing.T) {
	f := newAuditFixture(t)
	f.declareActions(t, "read", false)
	stub := &actionsStub{repo: workflowPermissions("read", false), org: workflowPermissions("read", true)}
	out, err := runPlanCmd(t, "--config="+f.manifestPath, "--remote", "--token=fixture", "--endpoint="+comparisonEndpoint(t, stub, &forgeStub{}))
	if err != nil {
		t.Fatalf("remote plan: %v\n%s", err, out)
	}
	requireIdentityFirst(t, stub.seen())
	mustContain(t, out, "  - compliant:", "Live branch protection of main on GitHub for acme/widgets")
}

// TestTransferredRepositoryRequiredChecks exercises the guarded job in both live comparisons.
// The old checkout has CI protected. The current repository also runs Transfer gate on each PR.
func TestTransferredRepositoryRequiredChecks(t *testing.T) {
	stub := &forgeStub{
		repo: map[string]any{
			"full_name": "new-org/imago", "owner": map[string]string{"login": "new-org"}, "visibility": "public",
		},
		rulesets: liveRuleset(t, declaredProtection(false), []string{"CI"}, "active"),
		runs:     map[string]map[string]any{"ci.yml": completedMainRunsPage(), "transfer.yml": completedMainRunsPage()},
	}
	f := protectedFixture(t, false, "", stub)
	guard := "if: github.repository == (vars.PRAETOR_CANONICAL_REPOSITORY || 'new-org/imago')"
	job := strings.Replace(prJobWorkflow("Transfer gate"), "runs-on:", guard+"\n    runs-on:", 1)
	f.commitWorkflows(t, map[string]string{"transfer.yml": job})
	f.recordOriginMain(t)
	const missing = "Required status checks: declared 2, live 1 of 2 required; missing: Transfer gate"
	t.Run("audit", func(t *testing.T) {
		_, err := f.audit(t)
		mustErrContain(t, err, missing)
	})
	t.Run("plan remote", func(t *testing.T) {
		out, err := runPlanCmd(t, "--config="+f.manifestPath, "--remote", "--token=fixture", "--endpoint="+actionsForgeEndpoint)
		if err != nil {
			t.Fatalf("remote plan: %v\n%s", err, out)
		}
		mustContain(t, out, "[DRIFT] "+missing, "Live branch protection of main on GitHub for new-org/imago")
	})
}

// TestAuditRepositoryVisibility_InvalidIdentity fails a visibility-only declaration even when public matches.
func TestAuditRepositoryVisibility_InvalidIdentity(t *testing.T) {
	for _, tc := range [...]struct{ name, login, want string }{
		{"inconsistent owner", "old-org", `owner.login "old-org" disagrees with full_name "new-org/imago"`},
		{"empty owner", "", `owner.login: invalid GitHub repository owner ""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &forgeStub{repo: map[string]any{
				"full_name": "new-org/imago", "owner": map[string]string{"login": tc.login}, "visibility": "public",
			}}
			f := visibilityFixture(t, "public", stub)
			out, err := f.audit(t)
			mustErrContain(t, err, "[FAIL] Repository visibility: read repository identity: "+tc.want)
			if strings.Contains(out, "[PASS] Repository visibility") {
				t.Fatalf("visibility passed with invalid identity:\n%s", out)
			}
		})
	}
}

// TestAuditRepositoryVisibility_Boundary_ForgeReadErrorFails names the failed repository GET.
func TestAuditRepositoryVisibility_Boundary_ForgeReadErrorFails(t *testing.T) {
	stub := &forgeStub{repoStatus: http.StatusInternalServerError}
	f := visibilityFixture(t, "public", stub)
	_, err := f.audit(t)
	mustErrContain(t, err, "[FAIL] Repository visibility: read repository identity: unexpected status 500")
}
