package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/gomanifest"
	"github.com/cordanaLLM/praetor/internal/testsupport"
)

const contractSubscription = "codex-cli/codex"

// TestWindowSnapshotZeroRecords checks the wire representations of a skip-only sync
// and the route refusal when the task's only lane needs a subscription reading.
func TestWindowSnapshotZeroRecords(t *testing.T) {
	const snapshot = `{
		"schema_version": 1,
		"generated_at": "2026-10-13T12:00:00Z",
		"records": [],
		"source_runs": [{"source": "gateway", "status": "skip", "count": 0}]
	}`
	path := routingInput(t, snapshot)
	t.Run("empty-array", func(t *testing.T) {
		requireWindowRoute(t, path, windowRecordID, windowNow, WindowUnknown, "window snapshot is empty")
	})
	t.Run("null", func(t *testing.T) {
		bad := mutateWindowFixture(t, path, `"records": []`, `"records": null`)
		requireWindowReadError(t, bad, "at '/records': got null, want array")
	})
	t.Run("missing", func(t *testing.T) {
		bad := mutateWindowFixture(t, path, `"records": [],`, "")
		requireWindowReadError(t, bad, "missing property 'records'")
	})
}

// windowContractCase selects one file or generation recipe and its producer expectations.
type windowContractCase struct {
	ID, File string
	Generate struct {
		From    string
		Records int
	}
	Expect struct {
		Result     string
		Says       string
		SourceRuns map[string]string `json:"source_runs"`
		Headroom   []struct {
			Now time.Time
		}
	}
}

// contractFixturePath confines manifest entries to the pinned module's fixture directory.
func contractFixturePath(t *testing.T, dir, name string) string {
	t.Helper()
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		t.Fatalf("invalid contract fixture name %q", name)
	}
	return filepath.Join(dir, name)
}

// contractFixtureBytes reads small producer inputs for mutations and size recipes.
func contractFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := contextopt.ReadSnapshot(testsupport.DeadlineContext(t), path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestWindowCatalogContract replays the RC's manifest at the consuming router.
func TestWindowCatalogContract(t *testing.T) {
	cache, ok := gomanifest.ModuleCacheRoot()
	if !ok {
		t.Fatal("cannot locate the Go module cache for the Epitrop contract fixtures")
	}
	module, err := gomanifest.ModuleCacheDir("github.com/tekmora/epitrop", "v0.3.0-rc.1")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, module, "catalog", "testdata", "contract")
	var manifest struct {
		Version int                  `json:"schema_version"`
		Limit   int                  `json:"max_records"`
		Cases   []windowContractCase `json:"cases"`
	}
	if err := json.Unmarshal(contractFixtureBytes(t, filepath.Join(dir, "cases.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	const caseCount = 10
	if manifest.Version != 1 || manifest.Limit != 25000 || len(manifest.Cases) != caseCount {
		t.Fatalf("unexpected catalog manifest version %d, limit %d, cases %d", manifest.Version, manifest.Limit, len(manifest.Cases))
	}
	for i := 0; i < caseCount; i++ {
		tc := manifest.Cases[i]
		t.Run(tc.ID, func(t *testing.T) { replayWindowContract(t, dir, tc) })
	}
}

// replayWindowContract checks generated inventories, refused inputs and admitted snapshots.
func replayWindowContract(t *testing.T, dir string, tc windowContractCase) {
	t.Helper()
	if tc.Generate.From != "" {
		checkWindowRecordLimit(t, contractFixturePath(t, dir, tc.Generate.From), tc)
		return
	}
	path := contractFixturePath(t, dir, tc.File)
	if tc.Expect.Result == "refused" {
		message := requireWindowReadError(t, path, tc.Expect.Says)
		if strings.HasSuffix(tc.ID, "-version") && !strings.Contains(message, "epitropctl sync --out") {
			t.Fatalf("missing migration command: %s", message)
		}
		return
	}
	checkWindowSourceRuns(t, path, tc)
	switch tc.ID {
	case "valid":
		checkValidContractWindow(t, path, tc.Expect.Headroom[0].Now)
		checkWindowEnvelope(t, path)
		checkWindowTimestampFormat(t, path)
		checkWindowByteLimit(t, path)
	case "stale":
		t.Run("at-max-age", func(t *testing.T) {
			requireWindowRoute(t, path, contractSubscription, tc.Expect.Headroom[0].Now, WindowWarn, "")
		})
		t.Run("over-max-age", func(t *testing.T) {
			requireWindowRoute(t, path, contractSubscription, tc.Expect.Headroom[1].Now, WindowUnknown, "stale")
		})
	case "unknown-headroom":
		checkUnknownContractWindows(t, path, tc.Expect.Headroom[0].Now)
	case "degraded":
		now := time.Date(2026, 10, 18, 9, 5, 0, 0, time.UTC)
		checkValidContractWindow(t, path, now)
		t.Run("failed-account", func(t *testing.T) {
			requireWindowRoute(t, path, "claude-code/session", now, WindowUnknown, "no subscription_cli reading")
		})
	default:
		t.Fatalf("unhandled catalog contract case %q", tc.ID)
	}
}

// checkWindowTimestampFormat distinguishes the RFC 3339 fraction separator from the comma
// that time.Time also accepts. Both cases change only generated_at in the same snapshot.
func checkWindowTimestampFormat(t *testing.T, path string) {
	t.Helper()
	const field = `"generated_at": "2026-10-18T09:00:00`
	t.Run("comma-fraction", func(t *testing.T) {
		bad := mutateWindowFixture(t, path, field+"Z", field+",5Z")
		message := requireWindowReadError(t, bad, "/generated_at")
		if !strings.Contains(message, "date-time") {
			t.Fatalf("expected date-time format refusal, got %s", message)
		}
	})
	t.Run("dot-fraction", func(t *testing.T) {
		good := mutateWindowFixture(t, path, field+"Z", field+".5Z")
		snapshot, err := LoadWindowSnapshot(testsupport.DeadlineContext(t), good)
		if err != nil {
			t.Fatal(err)
		}
		want := time.Date(2026, 10, 18, 9, 0, 0, 500_000_000, time.UTC)
		if !snapshot.GeneratedAt.Equal(want) {
			t.Fatalf("generated_at = %v, want %v", snapshot.GeneratedAt, want)
		}
	})
}

// checkWindowSourceRuns matches all producer outcomes, including the failed source's explanation.
func checkWindowSourceRuns(t *testing.T, path string, tc windowContractCase) {
	t.Helper()
	snapshot, err := LoadWindowSnapshot(testsupport.DeadlineContext(t), path)
	if err != nil {
		t.Fatal(err)
	}
	const maxFixtureRuns = 5
	if len(snapshot.SourceRuns) > maxFixtureRuns {
		t.Fatalf("unexpected source runs: %v", snapshot.SourceRuns)
	}
	got := make(map[string]string)
	for i := 0; i < len(snapshot.SourceRuns) && i < maxFixtureRuns; i++ {
		run := snapshot.SourceRuns[i]
		got[run.Source] = string(run.Status)
		switch run.Status {
		case "fail":
			checkContractOutcome(t, run.Count, run.Detail, 0, "session probe unreachable")
		case "degraded":
			checkContractOutcome(t, run.Count, run.Detail, 1, "litellm price map unavailable; OpenRouter records kept")
		}
	}
	if tc.ID == "degraded" && len(snapshot.Records) != 3 {
		t.Fatalf("expected three surviving records, got %d", len(snapshot.Records))
	}
	if !maps.Equal(got, tc.Expect.SourceRuns) {
		t.Fatalf("source statuses %v, want %v", got, tc.Expect.SourceRuns)
	}
}

// checkContractOutcome verifies the count and explanation accompanying a partial or failed source.
func checkContractOutcome(t *testing.T, count int, detail string, wantCount int, wantDetail string) {
	t.Helper()
	if count != wantCount || detail != wantDetail {
		t.Errorf("source outcome (%d, %q), want (%d, %q)", count, detail, wantCount, wantDetail)
	}
}

// requireWindowRoute builds the governor from the file and selects a task whose only lane is governed.
func requireWindowRoute(t *testing.T, path, record string, now time.Time, level WindowLevel, reason string) WindowDecision {
	t.Helper()
	ctx := testsupport.DeadlineContext(t)
	snapshot, err := LoadWindowSnapshot(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadWindowCatalog(t, windowCatalog)
	cfg.Governance.Window.MaxReadingAgeSeconds = 900
	cfg.Governance.Window.Accounts["max-a"] = WindowAccount{WindowRecord: record}
	governor, err := NewWindowGovernor(cfg, snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	arbiter := NewModelCapacityArbiter(cfg, nil)
	arbiter.Windows = governor
	decision := governor.Decide("max-a")
	if decision.Level != level || !strings.Contains(decision.Reason, reason) {
		t.Fatalf("record %s at %s: %+v, want %s (%s)", record, now, decision, level, reason)
	}
	route, err := arbiter.SelectForTask(ctx, TaskRequest{Task: "review"})
	return checkWindowAdmission(t, route, err, decision)
}

// checkWindowAdmission compares the governor decision with the route actually selected.
func checkWindowAdmission(t *testing.T, route *TaskRoute, err error, decision WindowDecision) WindowDecision {
	t.Helper()
	if decision.Level == WindowUnknown {
		if route != nil || !errors.Is(err, ErrNoEligibleModel) || !strings.Contains(err.Error(), decision.Reason) {
			t.Fatalf("expected lane refusal %q, got route %+v, error %v", decision.Reason, route, err)
		}
		return decision
	}
	if err != nil || route == nil || route.Window == nil || route.Window.Level != decision.Level {
		t.Fatalf("expected governed route %s, got %+v, error %v", decision.Level, route, err)
	}
	return *route.Window
}

// checkValidContractWindow verifies usage, burn and the pace shared across all three agents.
func checkValidContractWindow(t *testing.T, path string, now time.Time) {
	t.Helper()
	d := requireWindowRoute(t, path, contractSubscription, now, WindowWarn, "")
	if d.UsedPercent == nil || *d.UsedPercent != 42 || d.ProjectedBurnPercentPerHour == nil || *d.ProjectedBurnPercentPerHour != 12.5 {
		t.Fatalf("lost subscription usage or burn: %+v", d)
	}
	reset := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	want := (80 - 42) / reset.Sub(now).Hours() / 3
	if d.PacePercentPerAgentHour == nil || math.Abs(*d.PacePercentPerAgentHour-want) > 1e-9 {
		t.Fatalf("expected three-agent pace %v, got %+v", want, d)
	}
}

// checkUnknownContractWindows isolates each missing or out-of-date subscription fact.
func checkUnknownContractWindows(t *testing.T, path string, now time.Time) {
	t.Helper()
	const future = "claude-code/session"
	cases := [...]struct {
		name, record string
		offset       time.Duration
		level        WindowLevel
		reason       string
	}{
		{"missing-usage", contractSubscription, 0, WindowUnknown, "no used_percent"},
		{"future", future, 0, WindowUnknown, "dated in the future"},
		{"at-clock-skew", future, 4 * time.Minute, WindowOK, ""},
		{"over-clock-skew", future, 4*time.Minute - time.Second, WindowUnknown, "dated in the future"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireWindowRoute(t, path, tc.record, now.Add(tc.offset), tc.level, tc.reason)
		})
	}
	// The tagged ended window belongs to a gateway. Feed that same measurement to a governed subscription.
	t.Run("ended-window", func(t *testing.T) {
		ended := mutateWindowFixture(t, path, `"access_path": "gateway"`, `"access_path": "subscription_cli"`)
		requireWindowRoute(t, ended, "litellm-key/fleet", now, WindowUnknown, "ended window")
	})
}

// requireWindowReadError checks that the reader refuses before a governor can consume records.
func requireWindowReadError(t *testing.T, path, want string) string {
	t.Helper()
	snapshot, err := LoadWindowSnapshot(testsupport.DeadlineContext(t), path)
	if err == nil || !strings.Contains(err.Error(), want) || len(snapshot.Records) != 0 {
		t.Fatalf("expected read failure %q and zero records, got %v and %d", want, err, len(snapshot.Records))
	}
	return err.Error()
}

// mutateWindowFixture changes one known field in a temporary copy of the tagged fixture.
func mutateWindowFixture(t *testing.T, path, before, after string) string {
	t.Helper()
	data := contractFixtureBytes(t, path)
	if !bytes.Contains(data, []byte(before)) {
		t.Fatalf("fixture lacks mutation target %q", before)
	}
	return routingInput(t, strings.Replace(string(data), before, after, 1))
}

// checkWindowEnvelope plants fields accepted by the old decoder but outside the published schema.
func checkWindowEnvelope(t *testing.T, path string) {
	t.Helper()
	cases := [...]struct{ name, before, after, want string }{
		{"missing-generated-at", `"generated_at": "2026-10-18T09:00:00Z",`, "", "generated_at"},
		{"unknown-property", `"schema_version": 1`, `"schema_version": 1, "extra": true`, "extra"},
		{"unknown-status", `"status": "ok"`, `"status": "pending"`, "/source_runs/0/status"},
		{"duplicate-version", `"schema_version": 1`, `"schema_version": 2, "schema_version": 1`, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireWindowReadError(t, mutateWindowFixture(t, path, tc.before, tc.after), tc.want)
		})
	}
}
