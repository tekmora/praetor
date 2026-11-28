// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestReplayBucketReleasesMarkedFixtureText measures the live heap with and without
// the completed bucket's results. Capture storage stays live across both samples.
func TestReplayBucketReleasesMarkedFixtureText(t *testing.T) {
	bucket := markedFixtureBucket(t)
	live := heapWithReplayResults(t, bucket)
	released := liveHeapBytes()
	runtime.KeepAlive(bucket)
	if live > released+(1<<20) {
		t.Fatalf("256 replay results retain %d bytes, want at most 1 MiB", live-released)
	}
}

// markedFixtureBucket captures 256 distinct one-MiB headers. The short marker reason
// and kind sit in the same long line, so retaining either substring pins the payload.
func markedFixtureBucket(t *testing.T) bucketSnapshot {
	t.Helper()
	store := &fixtureStore{}
	t.Cleanup(func() {
		if err := store.close(); err != nil {
			t.Error(err)
		}
	})
	bucket := bucketSnapshot{stage: fixtureStage{"HISS-01", "go"}, store: store}
	for i := 0; i < 256; i++ {
		name := fmt.Sprintf("marked-%03d.opaque", i)
		data := bytes.Repeat([]byte{' '}, 1<<20)
		copy(data, "// hiss-fixture: unexamined: "+name)
		file, err := store.save(t.Context(), name, data)
		if err != nil {
			t.Fatal(err)
		}
		bucket.files = append(bucket.files, file)
	}
	return bucket
}

// heapWithReplayResults measures the heap after the real staging and scanner path has
// returned, while every marker result is still reachable.
func heapWithReplayResults(t *testing.T, bucket bucketSnapshot) uint64 {
	t.Helper()
	var report Report
	results, err := replayBucket(t.Context(), bucket, &report)
	if err != nil || len(results) != 256 || report.Fixtures != 256 {
		t.Fatalf("replayed %d fixtures, %d results, err %v", report.Fixtures, len(results), err)
	}
	for _, result := range results {
		if result.marked != intentionalUnexamined || result.markedReason != result.name {
			t.Fatalf("lost marker on %s", result.name)
		}
	}
	live := liveHeapBytes()
	runtime.KeepAlive(results)
	return live
}

// liveHeapBytes clears unreachable objects and the previous GC cycle's pool caches.
func liveHeapBytes() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// TestMarkerExcerptBound covers an exact fit, a cut through a multibyte character,
// and an invalid class long enough to otherwise fill a diagnostic with fixture text.
func TestMarkerExcerptBound(t *testing.T) {
	exact := strings.Repeat("a", 256)
	kind, reason, detail := parseMarkerSpec("unparsed: " + exact)
	if kind != intentionalUnparsed || reason != exact || detail != "" {
		t.Fatalf("exact reason: %q, %q, %q", kind, reason, detail)
	}
	prefix := strings.Repeat("b", 252)
	kind, reason, detail = parseMarkerSpec("unexamined: " + prefix + "界界")
	if kind != intentionalUnexamined || reason != prefix+"..." || !utf8.ValidString(reason) || detail != "" {
		t.Fatalf("truncated reason: %q, %q, %q", kind, reason, detail)
	}
	_, _, detail = parseMarkerSpec(strings.Repeat("z", 1<<20) + ": reason")
	if !strings.Contains(detail, "unknown hiss-fixture class") || len(detail) > 350 {
		t.Fatalf("invalid class diagnostic has %d bytes", len(detail))
	}
}
