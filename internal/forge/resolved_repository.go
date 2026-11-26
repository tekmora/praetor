// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/util"
)

// ResolvedRepository binds every live operation to the API base and repository from the identity GET.
type ResolvedRepository struct {
	apiBase    string
	owner      string
	name       string
	session    *repositorySession
	Visibility string
}

// repositorySession keeps the authenticated client separate from printable repository coordinates.
type repositorySession struct {
	token  string
	client http.Client
}

// ResolveRepository uses the checkout coordinates only for the initial identity request.
func ResolveRepository(ctx context.Context, token, endpoint, owner, name string) (ResolvedRepository, error) {
	if err := util.ValidateGitHubRepositoryIdentity(owner, name); err != nil {
		return ResolvedRepository{}, fmt.Errorf("%w: %w", ErrRepositoryIdentityRead, err)
	}
	reader := NewGitHubDriver(token, endpoint)
	reader.SetRepository(owner, name)
	return reader.ReadRepositorySettings(ctx)
}

// identityHTTPClient preserves the connection settings while bounding and checking each redirect.
func identityHTTPClient(base *http.Client) http.Client {
	var client http.Client
	if base != nil {
		client = *base
	}
	if client.Timeout <= 0 {
		client.Timeout = defaultHTTPTimeout
	}
	check := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("repository identity redirect limit exceeded")
		}
		origin := *via[0].URL
		if check != nil {
			if err := check(next, via); err != nil {
				return err
			}
		}
		if !sameAPIOrigin(&origin, next.URL) {
			return errors.New("repository identity redirect changes API origin")
		}
		return nil
	}
	return client
}

// sameAPIOrigin compares scheme, hostname and effective port, including explicit default ports.
func sameAPIOrigin(from, to *url.URL) bool {
	return strings.EqualFold(from.Scheme, to.Scheme) && strings.EqualFold(from.Hostname(), to.Hostname()) &&
		apiPort(from) == apiPort(to)
}

// apiPort supplies the default port when an HTTP or HTTPS URL omits it.
func apiPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// refuseRepositoryRedirect keeps a later read or mutation on the resource selected by the identity GET.
func refuseRepositoryRedirect(_ *http.Request, _ []*http.Request) error {
	return errors.New("resolved repository request redirected")
}

// FullName returns the validated owner/name for local workflow guards and reports.
func (r ResolvedRepository) FullName() string {
	if r.name == "" {
		return ""
	}
	return r.owner + "/" + r.name
}

// driver constructs a private driver from the resolved value. The caller cannot retarget it.
func (r ResolvedRepository) driver() *GitHubDriver {
	if r.session == nil {
		return &GitHubDriver{}
	}
	return &GitHubDriver{
		Token: r.session.token, Endpoint: r.apiBase, Owner: r.owner, Repo: r.name, HTTPClient: &r.session.client,
		RulesetName: RepositoryRulesetName, StrictStatusChecks: true,
	}
}

// WorkflowRunHistory reads the workflow runs of the resolved repository.
func (r ResolvedRepository) WorkflowRunHistory(ctx context.Context, workflow, branch string) (WorkflowRunHistory, error) {
	return r.driver().WorkflowRunHistory(ctx, workflow, branch)
}

// WorkflowRunJobs reads jobs of a run in the resolved repository.
func (r ResolvedRepository) WorkflowRunJobs(ctx context.Context, runID int64) ([]WorkflowJobRecord, error) {
	return r.driver().WorkflowRunJobs(ctx, runID)
}

// ReadBranchProtection reads the rulesets and legacy protection for branch.
func (r ResolvedRepository) ReadBranchProtection(ctx context.Context, branch string) (*LiveBranchProtection, error) {
	return r.driver().ReadBranchProtection(ctx, branch)
}

// ReconcileProtectionReport applies the managed branch ruleset with this repository's checks and refs.
func (r ResolvedRepository) ReconcileProtectionReport(ctx context.Context, branch string, policy *config.BranchProtectionPolicy, contexts []string) ([]LoweredParameter, []KeptParameter, error) {
	driver := r.driver()
	driver.ProtectedRefs = RepositoryRulesetRefs(branch)
	driver.RequiredStatusChecks = contexts
	return driver.ReconcileProtectionReport(ctx, branch, policy)
}

// ReconcileMergeQueue converges the managed queue ruleset on the resolved repository.
func (r ResolvedRepository) ReconcileMergeQueue(ctx context.Context, branch string, policy *config.BranchProtectionPolicy) ([]LoweredParameter, []KeptParameter, error) {
	return r.driver().ReconcileMergeQueue(ctx, branch, policy)
}

// LiveRuleset reads back the managed ruleset for branch.
func (r ResolvedRepository) LiveRuleset(ctx context.Context, branch string) ([]byte, error) {
	return r.driver().LiveRuleset(ctx, branch)
}

// ReconcileLabels applies the label taxonomy to the resolved repository.
func (r ResolvedRepository) ReconcileLabels(ctx context.Context, labels []Label) error {
	return r.driver().ReconcileLabels(ctx, labels)
}

// ReconcileRepositoryMetadata reconciles declared metadata at the resolved coordinates.
func (r ResolvedRepository) ReconcileRepositoryMetadata(ctx context.Context, declared config.RepositoryMetadata) (*RepositoryMetadataReport, error) {
	return r.driver().ReconcileRepositoryMetadata(ctx, declared)
}
