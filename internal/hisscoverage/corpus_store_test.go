// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"strings"
	"testing"
)

// TestSnapshotEightBucketsBoundRetainedBytes counts the actual backing arrays reachable
// from a captured corpus. Every bucket holds a distinct, maximum-size fixture.
func TestSnapshotEightBucketsBoundRetainedBytes(t *testing.T) {
	requireNativeReplay(t)
	root := t.TempDir()
	catalog := &Catalog{Version: 1}
	names := [...]string{bucketMeasured, bucketPositive, bucketNegative, bucketGap}
	for _, rule := range [...]string{"HISS-01", "HISS-02"} {
		catalog.Rules = append(catalog.Rules, catalogFor(rule, "go", StatePartial).Rules[0])
		for _, bucket := range names {
			body := largeFixtureText(rule, bucket)
			writeCorpusFixture(t, root, rule, "go", bucket, "fixture.go", body)
		}
	}
	var store fixtureStore
	t.Cleanup(func() {
		if err := store.close(); err != nil {
			t.Error(err)
		}
	})
	corpus, err := store.openCorpusSnapshot(t.Context(), root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	checkCapturedBuckets(t, root, corpus, &store)
}

// checkCapturedBuckets counts resident capacity and reads each original after replacement.
func checkCapturedBuckets(t *testing.T, root string, corpus corpusSnapshot, store *fixtureStore) {
	t.Helper()
	held, count := 0, 0
	for stage, claim := range corpus {
		for bucket, snapshot := range claim {
			if len(snapshot.files) != 1 {
				t.Fatalf("%s/%s captured %d fixtures", stage.ruleID, bucket, len(snapshot.files))
			}
			file := snapshot.files[0]
			held += cap(file.data)
			count++
			writeCorpusFixture(t, root, stage.ruleID, stage.language, bucket, file.name, "replacement")
			got, err := store.load(t.Context(), file)
			if err != nil || string(got) != largeFixtureText(stage.ruleID, bucket) {
				t.Fatalf("%s/%s lost its captured bytes: %v", stage.ruleID, bucket, err)
			}
		}
	}
	if count != 8 || held > 1<<20 {
		t.Fatalf("%d buckets hold %d bytes of fixture backing arrays, want 8 buckets and at most 1 MiB", count, held)
	}
}

// largeFixtureText returns one MiB of text carrying a distinct rule and bucket identity.
func largeFixtureText(rule, bucket string) string {
	prefix := rule + "/" + bucket + "\n"
	return prefix + strings.Repeat("x", (1<<20)-len(prefix))
}
