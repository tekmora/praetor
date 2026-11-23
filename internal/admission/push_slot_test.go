// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package admission

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

const holdPushSlotEnv = "PRAETOR_TEST_HOLD_PUSH_SLOT"

// TestPushSlot_Positive_TwoConcurrentSerial proves two push-slot waiters run one after the other.
func TestPushSlot_Positive_TwoConcurrentSerial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	pushSlotTestDir(t)
	var firstStart, firstEnd, secondStart time.Time
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		release, err := WaitPushSlot(context.Background(), 30*time.Second, 20*time.Millisecond, io.Discard)
		if err != nil {
			t.Errorf("first waiter: %v", err)
			return
		}
		firstStart = time.Now()
		time.Sleep(200 * time.Millisecond)
		firstEnd = time.Now()
		if err := release(); err != nil {
			t.Errorf("first release: %v", err)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	go func() {
		defer wg.Done()
		release, err := WaitPushSlot(context.Background(), 30*time.Second, 20*time.Millisecond, io.Discard)
		if err != nil {
			t.Errorf("second waiter: %v", err)
			return
		}
		secondStart = time.Now()
		if err := release(); err != nil {
			t.Errorf("second release: %v", err)
		}
	}()
	wg.Wait()
	if firstStart.IsZero() || secondStart.IsZero() || !secondStart.After(firstEnd) {
		t.Fatalf("overlap: first %v..%v second start %v", firstStart, firstEnd, secondStart)
	}
}

// TestPushSlot_Negative_DeadlineRefused proves a waiter past maxWait returns ErrPushSlotHeld.
func TestPushSlot_Negative_DeadlineRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	pushSlotTestDir(t)
	holding := make(chan struct{})
	go func() {
		release, err := WaitPushSlot(context.Background(), time.Hour, 20*time.Millisecond, io.Discard)
		if err != nil {
			t.Errorf("holder: %v", err)
			return
		}
		close(holding)
		time.Sleep(time.Hour)
		if err := release(); err != nil {
			t.Errorf("holder release: %v", err)
		}
	}()
	select {
	case <-holding:
	case <-time.After(2 * time.Second):
		t.Fatal("holder did not take the push slot")
	}
	_, err := WaitPushSlot(context.Background(), 400*time.Millisecond, 50*time.Millisecond, io.Discard)
	if err == nil || !errors.Is(err, ErrPushSlotHeld) || !strings.Contains(err.Error(), "still held") {
		t.Fatalf("deadline waiter: %v", err)
	}
}

// TestPushSlot_Boundary_KilledHolderFreesSlot proves SIGKILL on the holder admits the next waiter.
func TestPushSlot_Boundary_KilledHolderFreesSlot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	dir := pushSlotTestDir(t)
	kill := startPushSlotHolderSubprocess(t, dir)
	kill()
	release, err := WaitPushSlot(context.Background(), 5*time.Second, 50*time.Millisecond, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// startPushSlotHolderSubprocess runs this test binary as a push-slot holder (TestPushSlotSubprocessHolder)
// through util.RunCommandPassthrough, as startAdmitSubprocessLeaseHolder does for executor leases. It
// returns once the holder reports the slot taken; the returned function kills the holder through its
// command context, so the slot is never released by the holder itself.
func startPushSlotHolderSubprocess(t *testing.T, runtimeDir string) func() {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyR, readyW := io.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		runErr := util.RunCommandPassthrough(ctx, "", "env", nil, readyW, &stderr,
			holdPushSlotEnv+"=1", "XDG_RUNTIME_DIR="+runtimeDir, self, "-test.run=^TestPushSlotSubprocessHolder$", "-test.count=1")
		done <- errors.Join(runErr, readyW.Close())
	}()
	var ack [1]byte
	if _, err := io.ReadFull(readyR, ack[:]); err != nil {
		cancel()
		t.Fatalf("push slot holder failed to start: %v (%s)", err, stderr.String())
	}
	return func() {
		cancel()
		if _, err := io.Copy(io.Discard, readyR); err != nil {
			t.Errorf("drain push slot holder: %v", err)
		}
		if err := <-done; err == nil {
			t.Errorf("push slot holder exited cleanly; want it killed (%s)", stderr.String())
		}
	}
}

// TestPushSlotSubprocessHolder holds the push slot, reports it taken with one byte on stdout, and waits
// until its parent kills it.
func TestPushSlotSubprocessHolder(t *testing.T) {
	if os.Getenv(holdPushSlotEnv) != "1" {
		return
	}
	release, err := WaitPushSlot(context.Background(), time.Hour, time.Second, io.Discard)
	if err != nil {
		t.Fatalf("holder: %v", err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("holder release: %v", err)
		}
	}()
	if _, err := os.Stdout.Write([]byte{'1'}); err != nil {
		t.Fatalf("holder ready: %v", err)
	}
	time.Sleep(time.Hour)
}

// TestPushSlot_Boundary_LeaseDirMatchesExecutorLayout proves push slot uses the shared lease tree.
func TestPushSlot_Boundary_LeaseDirMatchesExecutorLayout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	runtimeDir := pushSlotTestDir(t)
	want := filepath.Join(runtimeDir, executorLeasesDir, PushSlotLeaseResource)
	got, err := leaseResourceDir(PushSlotLeaseResource, "push slot")
	if err != nil || got != want {
		t.Fatalf("push slot dir = %q, want %q (%v)", got, want, err)
	}
	release, err := WaitPushSlot(context.Background(), time.Second, 10*time.Millisecond, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	assertPushSlotEmpty(t)
}

// pushSlotTestDir points the runtime directory at a fresh temporary folder so each test has its own push slot.
func pushSlotTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

// assertPushSlotEmpty fails the test when a push slot lease file is still present.
func assertPushSlotEmpty(t *testing.T) {
	t.Helper()
	dir, err := leaseResourceDir(PushSlotLeaseResource, "push slot")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(entries) && i < maxExecutorLeaseDirEntries; i++ {
		if strings.HasSuffix(entries[i].Name(), ".lock") {
			t.Fatalf("leftover push slot lease %s", entries[i].Name())
		}
	}
}
