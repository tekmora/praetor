package router

import (
	"encoding/json"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/testsupport"
)

// generatedWindowInput repeats the seed's first record with distinct IDs, as the RC manifest specifies.
func generatedWindowInput(t *testing.T, seed string, count int) string {
	t.Helper()
	const maxPlant = 25001
	if count < 1 || count > maxPlant {
		t.Fatalf("invalid generated fixture size %d", count)
	}
	var envelope struct {
		Version    int              `json:"schema_version"`
		Generated  time.Time        `json:"generated_at"`
		Records    []map[string]any `json:"records"`
		SourceRuns json.RawMessage  `json:"source_runs"`
	}
	if err := json.Unmarshal(contractFixtureBytes(t, seed), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Records) == 0 {
		t.Fatal("catalog size fixture needs a seed record")
	}
	base := envelope.Records[0]
	if base["model_id"] != contractSubscription {
		t.Fatalf("unexpected seed record %v", base["model_id"])
	}
	envelope.Records = make([]map[string]any, count)
	for i := 0; i < count && i < maxPlant; i++ {
		row := maps.Clone(base)
		row["model_id"] = contractSubscription + "-" + strconv.Itoa(i)
		envelope.Records[i] = row
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= 1<<20 {
		t.Fatalf("generated contract case has only %d bytes", len(data))
	}
	return routingInput(t, string(data))
}

// checkWindowRecordLimit exercises the producer's cap and the first count beyond the legacy cap.
func checkWindowRecordLimit(t *testing.T, seed string, tc windowContractCase) {
	t.Helper()
	count := tc.Generate.Records
	if tc.Expect.Result == "refused" {
		requireWindowReadError(t, generatedWindowInput(t, seed, count), "record count before decode: "+tc.Expect.Says)
		return
	}
	for _, size := range [...]int{20001, count} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := generatedWindowInput(t, seed, size)
			last := contractSubscription + "-" + strconv.Itoa(size-1)
			now := time.Date(2026, 10, 18, 9, 5, 0, 0, time.UTC)
			requireWindowRoute(t, path, last, now, WindowWarn, "")
		})
	}
}

// TestWindowRecordCountStopsAtFirstExcessToken leaves record 25,001 unfinished. A decoder
// that reads its contents, or attempts to decode the first number as a record, fails differently.
func TestWindowRecordCountStopsAtFirstExcessToken(t *testing.T) {
	const want = "record count before decode: snapshot has 25001 records, exceeds 25000"
	for _, member := range [...]string{"records", `rec\u006frds`, "RECORDS"} {
		t.Run(member, func(t *testing.T) {
			body := `{"` + member + `":[` + strings.Repeat("0,", 25000) + "{"
			requireWindowReadError(t, routingInput(t, body), want)
		})
	}
}

// checkWindowByteLimit pads valid JSON with spaces so only the file's size changes.
func checkWindowByteLimit(t *testing.T, seed string) {
	t.Helper()
	const limit = 64 << 20
	body := string(contractFixtureBytes(t, seed))
	padded := body + strings.Repeat(" ", limit+1-len(body))
	now := time.Date(2026, 10, 18, 9, 5, 0, 0, time.UTC)
	t.Run("over-1-MiB", func(t *testing.T) {
		path := routingInput(t, padded[:(1<<20)+1])
		requireWindowRoute(t, path, contractSubscription, now, WindowWarn, "")
		ctx := testsupport.DeadlineContext(t)
		if _, err := LoadRoutingConfigContext(ctx, path); err == nil || !strings.Contains(err.Error(), "1 MiB") {
			t.Fatalf("expected routing file size refusal, got %v", err)
		}
		if _, err := LoadUsageSnapshot(ctx, path); err == nil || !strings.Contains(err.Error(), "1 MiB") {
			t.Fatalf("expected usage file size refusal, got %v", err)
		}
	})
	t.Run("64-MiB", func(t *testing.T) {
		requireWindowRoute(t, routingInput(t, padded[:limit]), contractSubscription, now, WindowWarn, "")
	})
	t.Run("64-MiB-plus-one", func(t *testing.T) {
		requireWindowReadError(t, routingInput(t, padded), "64 MiB")
	})
}
