// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/admission"
)

// TestParseAdmit_Boundary_PushClass proves --class push is accepted and other values refused.
func TestParseAdmit_Boundary_PushClass(t *testing.T) {
	opts, err := parseAdmit([]string{"--class", "push", "--local", "--wait", "1m", "--", "true"})
	if err != nil || opts.admitClass != admitClassPush {
		t.Fatalf("push class: %+v, %v", opts, err)
	}
	if _, err := parseAdmit([]string{"--class", "lane", "--", "true"}); err == nil || !strings.Contains(err.Error(), "use push") {
		t.Fatalf("invalid class: %v", err)
	}
}

// TestRunAdmit_PushClass_NonPushUnaffected proves default admit does not take the push slot.
func TestRunAdmit_PushClass_NonPushUnaffected(t *testing.T) {
	needShell(t)
	admitStubTools(t)
	if err := runAdmit([]string{"--local", "--min-available-gib", "0", "--min-swap-free-gib", "0", "--max-load", "0",
		"--", "sh", "-c", "exit 0"}); err != nil {
		t.Fatal(err)
	}
}

// TestRunAdmit_PushClass_TwoConcurrentSerial proves two push-class steps do not overlap.
func TestRunAdmit_PushClass_TwoConcurrentSerial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	needShell(t)
	admitStubTools(t)
	slotBase := admission.PushSlotTestBase(t)
	marker := filepath.Join(slotBase, "timeline")
	runConcurrentPushClassAdmits(t, marker)
	byTag := parsePushClassTimeline(t, marker)
	assertPushClassSpansNonOverlapping(t, byTag)
}

// pushClassConcurrentScript returns argv for one push-class admit step that records start and end in marker.
func pushClassConcurrentScript(tag, marker string) []string {
	return []string{"--class", "push", "--local", "--min-available-gib", "0", "--min-swap-free-gib", "0",
		"--max-load", "0", "--wait", "2m", "--poll", "20ms", "--label", tag, "--",
		"sh", "-c", `printf "%s start %s\n" "` + tag + `" $(date +%s%N) >> "` + marker + `"; ` +
			`sleep 0.2; printf "%s end %s\n" "` + tag + `" $(date +%s%N) >> "` + marker + `"`}
}

// runConcurrentPushClassAdmits launches two push-class admits, one per tag, against marker.
func runConcurrentPushClassAdmits(t *testing.T, marker string) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(2)
	for _, tag := range []string{"a", "b"} {
		go func(tag string) {
			defer wg.Done()
			if err := runAdmit(pushClassConcurrentScript(tag, marker)); err != nil {
				t.Errorf("%s: %v", tag, err)
			}
		}(tag)
	}
	wg.Wait()
}

type pushClassSpan struct {
	tag            string
	startNs, endNs uint64
}

// parsePushClassTimeline reads marker lines into a map keyed by tag.
func parsePushClassTimeline(t *testing.T, marker string) map[string]*pushClassSpan {
	t.Helper()
	byTag := map[string]*pushClassSpan{}
	lines := strings.Split(strings.TrimSpace(string(readFile(t, marker))), "\n")
	for i := 0; i < len(lines) && i < maxPushClassTimelineLines; i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("timeline line: %q", line)
		}
		ts, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		slot := byTag[fields[0]]
		if slot == nil {
			slot = &pushClassSpan{tag: fields[0]}
			byTag[fields[0]] = slot
		}
		if fields[1] == "start" {
			slot.startNs = ts
		} else {
			slot.endNs = ts
		}
	}
	return byTag
}

const maxPushClassTimelineLines = 16

// assertPushClassSpansNonOverlapping fails when the two recorded spans overlap in time.
func assertPushClassSpansNonOverlapping(t *testing.T, byTag map[string]*pushClassSpan) {
	t.Helper()
	if len(byTag) != 2 {
		t.Fatalf("timeline tags: %+v", byTag)
	}
	var list [2]pushClassSpan
	i := 0
	for _, slot := range byTag {
		if slot.startNs == 0 || slot.endNs == 0 {
			t.Fatalf("incomplete span: %+v", slot)
		}
		list[i] = *slot
		i++
	}
	first, second := list[0], list[1]
	if first.startNs > second.startNs {
		first, second = second, first
	}
	if second.startNs < first.endNs {
		t.Fatalf("overlap: %+v then %+v", first, second)
	}
}

// TestRunAdmit_PushClass_WaiterDeadline proves a push-class waiter past --wait exits with ErrPushSlotHeld.
func TestRunAdmit_PushClass_WaiterDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	needShell(t)
	admitStubTools(t)
	admission.PushSlotTestBase(t)
	holding, waitHolder := startPushSlotHolderForTest(t)
	select {
	case <-holding:
	case <-time.After(2 * time.Second):
		t.Fatal("holder blocked")
	}
	err := runAdmit([]string{"--class", "push", "--local", "--min-available-gib", "0", "--min-swap-free-gib", "0",
		"--max-load", "0", "--wait", "500ms", "--poll", "50ms", "--", "sh", "-c", "exit 0"})
	if err == nil || !errors.Is(err, admission.ErrPushSlotHeld) {
		t.Fatalf("waiter: %v", err)
	}
	waitHolder()
}

// startPushSlotHolderForTest runs a push-slot holder until t ends or the returned wait function runs.
func startPushSlotHolderForTest(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	holderCtx, holderStop := context.WithCancel(context.Background())
	holding := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		release, err := admission.WaitPushSlot(holderCtx, time.Hour, 20*time.Millisecond, io.Discard)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Errorf("holder: %v", err)
			}
			return
		}
		close(holding)
		<-holderCtx.Done()
		if err := release(); err != nil {
			t.Errorf("holder release: %v", err)
		}
	}()
	t.Cleanup(func() {
		holderStop()
		<-holderDone
	})
	return holding, func() {
		holderStop()
		<-holderDone
	}
}

// TestRunAdmit_PushClass_Boundary_ImmediateAcquireAfterHolder proves the slot is free once a test holder is torn down.
func TestRunAdmit_PushClass_Boundary_ImmediateAcquireAfterHolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	needShell(t)
	admitStubTools(t)
	admission.PushSlotTestBase(t)
	holding, waitHolder := startPushSlotHolderForTest(t)
	select {
	case <-holding:
	case <-time.After(2 * time.Second):
		t.Fatal("holder blocked")
	}
	waitHolder()
	if err := runAdmit([]string{"--class", "push", "--local", "--min-available-gib", "0", "--min-swap-free-gib", "0",
		"--max-load", "0", "--wait", "10s", "--poll", "50ms", "--", "sh", "-c", "exit 0"}); err != nil {
		t.Fatalf("immediate acquire after holder cleanup: %v", err)
	}
}

// readFile returns the file contents or fails the test.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
