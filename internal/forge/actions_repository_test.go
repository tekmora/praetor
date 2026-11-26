// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/config"
)

const (
	fixtureRepository = "/repos/old-org/imago"
	workflowSuffix    = "/actions/permissions/workflow"
	approvalDenied    = `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`
	approvalAllowed   = `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}`
)

// repositoryReply describes one in-memory response, including a redirect when location is set.
type repositoryReply struct {
	status   int
	body     string
	location string
}

// repositoryTransport serves only the listed repository and organisation GETs without a socket.
type repositoryTransport struct {
	replies map[string]repositoryReply
	paths   []string
}

// RoundTrip records each read and returns its fixture response to the driver's redirect-aware client.
func (f *repositoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	path := r.URL.Path
	f.paths = append(f.paths, path)
	reply, ok := f.replies[path]
	if !ok || r.Method != http.MethodGet {
		return nil, fmt.Errorf("unexpected %s %s", r.Method, path)
	}
	header := make(http.Header)
	if reply.location != "" {
		header.Set("Location", reply.location)
	}
	return &http.Response{StatusCode: reply.status, Header: header, Body: io.NopCloser(strings.NewReader(reply.body))}, nil
}

// read starts at the clone's configured owner and name and executes only against this transport.
func (f *repositoryTransport) read(t *testing.T) (LiveWorkflowPermissions, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultHTTPTimeout)
	defer cancel()
	return f.driver().WorkflowPermissions(ctx)
}

// driver configures the bootstrap reader with the old coordinates and the in-memory transport.
func (f *repositoryTransport) driver() *GitHubDriver {
	driver := NewGitHubDriver("fixture", "https://forge.invalid")
	driver.SetRepository("old-org", "imago")
	driver.HTTPClient.Transport = f
	return driver
}

// repositoryFixture answers old repository permission URLs as a transferred repository would.
// A client using the stale organisation therefore receives a real but different permission value.
func repositoryFixture(owner, name string) (*repositoryTransport, []string) {
	fullName := owner + "/" + name
	current := "/repos/" + fullName
	org := "/orgs/" + owner + workflowSuffix
	replies := map[string]repositoryReply{
		fixtureRepository + workflowSuffix: {status: http.StatusOK, body: approvalDenied},
		"/orgs/old-org" + workflowSuffix:   {status: http.StatusOK, body: approvalAllowed},
	}
	replies[current] = repositoryReply{status: http.StatusOK, body: fmt.Sprintf(`{"full_name":%q,"owner":{"login":%q}}`, fullName, owner)}
	replies[current+workflowSuffix] = repositoryReply{status: http.StatusOK, body: approvalDenied}
	paths := []string{fixtureRepository}
	if current != fixtureRepository {
		replies[fixtureRepository] = repositoryReply{status: http.StatusMovedPermanently, location: current}
		paths = append(paths, current)
	}
	if owner != "old-org" {
		replies[org] = repositoryReply{status: http.StatusOK, body: approvalDenied}
	}
	return &repositoryTransport{replies: replies}, append(paths, current+workflowSuffix, org)
}

// TestWorkflowPermissionsRepositoryIdentity checks the verdict and the precise repository and
// organisation selected after a transfer, a same-owner rename, and an unchanged repository.
func TestWorkflowPermissionsRepositoryIdentity(t *testing.T) {
	cases := [...]struct {
		label, owner, name string
		approve            bool
		want               ActionsVerdict
	}{
		{"transfer", "new-org", "imago", true, ActionsBlockedByOrganisation},
		{"transfer matching declaration", "new-org", "imago", false, ActionsCompliant},
		{"unchanged", "old-org", "imago", false, ActionsCompliant},
		{"renamed", "old-org", "new-name", false, ActionsCompliant},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			stub, paths := repositoryFixture(tc.owner, tc.name)
			live, err := stub.read(t)
			if err != nil {
				t.Fatal(err)
			}
			declared := config.ActionsPolicy{DefaultWorkflowPermissions: "read", AllowCreateAndApprovePullRequests: tc.approve}
			if got := EvaluateLiveActionsPermissions(declared, live); got.Verdict != tc.want {
				t.Fatalf("verdict %s, want %s (%s)", got.Verdict, tc.want, got.Detail)
			}
			if !slices.Equal(stub.paths, paths) {
				t.Fatalf("requests %v, want %v", stub.paths, paths)
			}
		})
	}
}

// TestWorkflowPermissionsUnreadableRepository verifies failed and inconsistent identity reads
// stop before either permissions endpoint, even when the stale coordinates would answer.
func TestWorkflowPermissionsUnreadableRepository(t *testing.T) {
	cases := [...]struct {
		label, body, detail string
		status              int
	}{
		{"refused", "", "503", http.StatusServiceUnavailable},
		{"malformed JSON", "{", "parse repository metadata", http.StatusOK},
		{"missing owner", `{"full_name":"new-org/imago"}`, "owner.login", http.StatusOK},
		{"missing full name", `{"owner":{"login":"new-org"}}`, "full_name", http.StatusOK},
		{"disagreement", `{"owner":{"login":"old-org"},"full_name":"new-org/imago"}`, "disagrees", http.StatusOK},
		{"invalid name", `{"owner":{"login":"new-org"},"full_name":"new-org/.."}`, "full_name", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			stub, _ := repositoryFixture("old-org", "imago")
			stub.replies[fixtureRepository] = repositoryReply{status: tc.status, body: tc.body}
			_, err := stub.read(t)
			if err == nil || !strings.Contains(err.Error(), "read repository identity") || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("identity read error = %v, want named failure containing %q", err, tc.detail)
			}
			if !slices.Equal(stub.paths, []string{fixtureRepository}) {
				t.Fatalf("requests after repository read failed = %v", stub.paths)
			}
		})
	}
}

// TestRepositoryIdentityRedirectOrigin checks scheme, hostname and port on every redirect hop.
func TestRepositoryIdentityRedirectOrigin(t *testing.T) {
	const current = "/repos/new-org/imago"
	for _, tc := range [...]struct {
		origin string
		allow  bool
	}{
		{"https://FORGE.invalid:443", true},
		{"http://forge.invalid", false},
		{"https://other.invalid", false},
		{"https://forge.invalid:444", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			stub, paths := repositoryFixture("new-org", "imago")
			stub.replies[fixtureRepository] = repositoryReply{status: http.StatusFound, location: "/redirect"}
			stub.replies["/redirect"] = repositoryReply{status: http.StatusFound, location: tc.origin + current}
			_, err := stub.read(t)
			want := []string{fixtureRepository, "/redirect"}
			if tc.allow {
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, paths[1:]...)
			} else if !errors.Is(err, ErrRepositoryIdentityRead) {
				t.Errorf("identity error = %v, want ErrRepositoryIdentityRead", err)
			}
			if !slices.Equal(stub.paths, want) {
				t.Errorf("requests = %v, want %v", stub.paths, want)
			}
		})
	}
}

// TestResolvedPermissionsRefuseRedirect rejects an attempt to read another repository's permissions.
func TestResolvedPermissionsRefuseRedirect(t *testing.T) {
	stub, _ := repositoryFixture("new-org", "imago")
	const current = "/repos/new-org/imago"
	stub.replies[current+workflowSuffix] = repositoryReply{
		status: http.StatusTemporaryRedirect, location: fixtureRepository + workflowSuffix,
	}
	_, err := stub.read(t)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("redirected permissions error = %v", err)
	}
	if want := []string{fixtureRepository, current, current + workflowSuffix}; !slices.Equal(stub.paths, want) {
		t.Errorf("requests = %v, want %v", stub.paths, want)
	}
}

// TestResolvedRepositoryKeepsConnection checks that retargeting the bootstrap driver cannot move a snapshot.
func TestResolvedRepositoryKeepsConnection(t *testing.T) {
	current, paths := repositoryFixture("new-org", "imago")
	other, _ := repositoryFixture("new-org", "imago")
	reader := current.driver()
	ctx, cancel := context.WithTimeout(t.Context(), defaultHTTPTimeout)
	defer cancel()
	repository, err := reader.ReadRepositorySettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader.Endpoint = "https://other.invalid"
	reader.SetRepository("other-org", "other-repo")
	reader.HTTPClient.Transport = other
	if _, err := repository.WorkflowPermissions(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(current.paths, paths) || len(other.paths) != 0 {
		t.Errorf("permission reads moved with the bootstrap driver: current %v, other %v", current.paths, other.paths)
	}
}
