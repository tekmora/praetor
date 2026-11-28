// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

const holdPushSlotEnv = "PRAETOR_TEST_HOLD_PUSH_SLOT"
const childPushSlotBaseEnv = "PRAETOR_TEST_HOLD_PUSH_SLOT_BASE"

// TestPushSlot_Positive_SingleGrant proves one published queue lease can take the holder lock.
func TestPushSlot_Positive_SingleGrant(t *testing.T) {
	pushSlotTestDir(t)
	slotDir, err := pushSlotLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(slotDir)
	if err != nil {
		t.Fatal(err)
	}
	ownName, releaseLease, err := createPushSlotLease(slotDir, root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := releaseLease(); err != nil {
			t.Fatal(err)
		}
	}()
	granted, releaseHolder, err := tryGrantPushSlot(ownName, root)
	if err != nil || !granted {
		t.Fatalf("grant = %v err %v", granted, err)
	}
	if err := releaseHolder(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPushSlot_Positive_TwoConcurrentSerial proves two push-slot waiters run one after the other.
func TestPushSlot_Positive_TwoConcurrentSerial(t *testing.T) {
	pushSlotTestDir(t)
	firstHolding := make(chan struct{})
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
		close(firstHolding)
		time.Sleep(200 * time.Millisecond)
		firstEnd = time.Now()
		if err := release(); err != nil {
			t.Errorf("first release: %v", err)
		}
	}()
	select {
	case <-firstHolding:
	case <-time.After(5 * time.Second):
		t.Fatal("first waiter did not take the push slot")
	}
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

// TestPushSlot_Negative_ReversedQueueDoesNotOverlap proves the holder lock keeps one runner when a newer queue lease leads while an older lease joins the queue.
func TestPushSlot_Negative_ReversedQueueDoesNotOverlap(t *testing.T) {
	fixture := openReversedQueueFixture(t)
	overlap, active := &atomic.Bool{}, &atomic.Int32{}
	holding := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go reversedQueueRunNewerHolder(t, &wg, fixture, overlap, active, holding)
	waitReversedQueueNewerHolding(t, holding)
	go reversedQueueRunOlderWaiter(t, &wg, fixture, overlap, active)
	wg.Wait()
	if overlap.Load() {
		t.Fatal("two push slot holders ran at once after reversed queue order")
	}
}

// reversedQueueFixture holds a push-slot root with a newer queue lease already published.
type reversedQueueFixture struct {
	slotDir, newName, oldName string
	root                      *os.Root
}

// openReversedQueueFixture creates the newer queue lease file and opens the slot root for reversed-order tests.
func openReversedQueueFixture(t *testing.T) reversedQueueFixture {
	t.Helper()
	pushSlotTestDir(t)
	slotDir, err := pushSlotLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(slotDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close slot root: %v", err)
		}
	})
	newName := fmt.Sprintf("%020d-%d-new.lock", 2, os.Getpid())
	oldName := fmt.Sprintf("%020d-%d-old.lock", 1, os.Getpid())
	_, releaseNew, err := createLockedLease("push slot", slotDir, root, newName, pushSlotLockLabel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := releaseNew(); err != nil {
			t.Errorf("release newer queue lease: %v", err)
		}
	})
	return reversedQueueFixture{slotDir: slotDir, newName: newName, oldName: oldName, root: root}
}

// waitReversedQueueNewerHolding fails when the newer holder does not take the slot within the deadline.
func waitReversedQueueNewerHolding(t *testing.T, holding <-chan struct{}) {
	t.Helper()
	select {
	case <-holding:
	case <-time.After(2 * time.Second):
		t.Fatal("newer holder did not take the slot")
	}
}

// reversedQueueRunNewerHolder grants the newer lease the holder lock and signals when it runs.
func reversedQueueRunNewerHolder(t *testing.T, wg *sync.WaitGroup, fix reversedQueueFixture, overlap *atomic.Bool, active *atomic.Int32, holding chan struct{}) {
	t.Helper()
	defer wg.Done()
	granted, releaseHolder, err := tryGrantPushSlot(fix.newName, fix.root)
	if err != nil || !granted {
		t.Errorf("newer holder: granted=%v err=%v", granted, err)
		return
	}
	if active.Add(1) != 1 {
		overlap.Store(true)
	}
	close(holding)
	time.Sleep(200 * time.Millisecond)
	active.Add(-1)
	if err := releaseHolder(); err != nil {
		t.Errorf("newer release holder: %v", err)
	}
}

// reversedQueueRunOlderWaiter polls until the older queue lease can take the holder without overlapping the newer run.
func reversedQueueRunOlderWaiter(t *testing.T, wg *sync.WaitGroup, fix reversedQueueFixture, overlap *atomic.Bool, active *atomic.Int32) {
	t.Helper()
	defer wg.Done()
	_, releaseOld, err := createLockedLease("push slot", fix.slotDir, fix.root, fix.oldName, pushSlotLockLabel)
	if err != nil {
		t.Errorf("older lease: %v", err)
		return
	}
	defer func() {
		if err := releaseOld(); err != nil {
			t.Errorf("release older queue lease: %v", err)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		granted, releaseOlderHolder, err := tryGrantPushSlot(fix.oldName, fix.root)
		if err != nil {
			t.Errorf("older holder: %v", err)
			return
		}
		if granted {
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			active.Add(-1)
			if err := releaseOlderHolder(); err != nil {
				t.Errorf("older release holder: %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("older lease never acquired the holder after newer release")
}

// TestPushSlot_TestMain_IsolatedFromHostRuntime proves TestMain keeps the resolved slot off the host runtime tree.
func TestPushSlot_TestMain_IsolatedFromHostRuntime(t *testing.T) {
	got, err := pushSlotLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv(pushSlotTestBaseEnv)
	if base == "" || got != filepath.Join(base, pushSlotQueueDir) {
		t.Fatalf("push slot dir %q is outside test runtime %q", got, base)
	}
}

// TestPushSlot_Positive_SameDirIgnoresRuntimeEnv proves XDG_RUNTIME_DIR and TMPDIR do not fork the push slot queue.
func TestPushSlot_Positive_SameDirIgnoresRuntimeEnv(t *testing.T) {
	root := t.TempDir()
	makePushSlotFixtureDir(t, filepath.Join(root, systemTempRoot))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	first, err := hostPushSlotRuntimeBaseAt(root, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "other-xdg"))
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "other-tmp"))
	second, err := hostPushSlotRuntimeBaseAt(root, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("push slot dir drifted: %q vs %q", first, second)
	}
}

// TestPushSlot_Boundary_WaitShorterThanPollAcquires proves a short maxWait with a long poll still acquires when the holder releases in time.
func TestPushSlot_Boundary_WaitShorterThanPollAcquires(t *testing.T) {
	pushSlotTestDir(t)
	holding := make(chan struct{})
	go func() {
		release, err := WaitPushSlot(context.Background(), time.Hour, time.Millisecond, io.Discard)
		if err != nil {
			t.Errorf("holder: %v", err)
			return
		}
		close(holding)
		time.Sleep(150 * time.Millisecond)
		if err := release(); err != nil {
			t.Errorf("holder release: %v", err)
		}
	}()
	select {
	case <-holding:
	case <-time.After(5 * time.Second):
		t.Fatal("holder did not take the push slot")
	}
	release, err := WaitPushSlot(context.Background(), 500*time.Millisecond, time.Minute, io.Discard)
	if err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// TestPushSlot_Negative_DeadlineRefused proves a waiter past maxWait returns ErrPushSlotHeld.
func TestPushSlot_Negative_DeadlineRefused(t *testing.T) {
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
	if err == nil || !errors.Is(err, ErrPushSlotHeld) {
		t.Fatalf("deadline waiter: %v", err)
	}
}

// TestPushSlot_Negative_WaitShorterThanPollRefuses proves a long poll does not refuse before maxWait when the slot stays held.
func TestPushSlot_Negative_WaitShorterThanPollRefuses(t *testing.T) {
	pushSlotTestDir(t)
	holding := make(chan struct{})
	go func() {
		release, err := WaitPushSlot(context.Background(), time.Hour, time.Millisecond, io.Discard)
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
	start := time.Now()
	_, err := WaitPushSlot(context.Background(), 300*time.Millisecond, time.Minute, io.Discard)
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, ErrPushSlotHeld) {
		t.Fatalf("waiter: %v", err)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("refused too early after %v with poll longer than maxWait", elapsed)
	}
}

// TestReview2044ExecutorPreservesPushHolderInode proves a valid host-push executor cannot remove the persistent holder.
func TestReview2044ExecutorPreservesPushHolderInode(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", pushSlotTestDir(t))
	releaseHolder := holdPushSlotForTest(t)
	if err := releaseHolder(); err != nil {
		t.Fatal(err)
	}
	dir, err := pushSlotLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, pushSlotHolderName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	count, releaseExecutor, err := AdmitExecutorLease("host-push")
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseExecutor(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("host-push executor count = %d, want 1", count)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatalf("host-push executor changed the holder inode: %v", err)
	}
}

// TestReview2044CanceledWaiterDoesNotAcquire cancels a queued waiter while releasing the current holder.
func TestReview2044CanceledWaiterDoesNotAcquire(t *testing.T) {
	pushSlotTestDir(t)
	releaseHolder := holdPushSlotForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := pushSlotWriterFunc(func(p []byte) (int, error) {
		cancel()
		return len(p), releaseHolder()
	})
	release, err := WaitPushSlot(ctx, time.Second, time.Second, log)
	if release != nil {
		t.Fatalf("canceled waiter acquired the slot: error %v, release %v", err, release())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context.Canceled", err)
	}
	assertPushSlotEmpty(t)
}

// TestReview2044QueueLogFailurePreserved proves a queue writer error reaches the caller.
func TestReview2044QueueLogFailurePreserved(t *testing.T) {
	pushSlotTestDir(t)
	holdPushSlotForTest(t)
	logErr := errors.New("queue writer failed")
	log := pushSlotWriterFunc(func([]byte) (int, error) { return 0, logErr })
	release, err := WaitPushSlot(t.Context(), time.Second, time.Second, log)
	if release != nil {
		t.Fatalf("waiter acquired the held slot: error %v, release %v", err, release())
	}
	if !errors.Is(err, logErr) {
		t.Fatalf("wait error = %v, want %v", err, logErr)
	}
}

// pushSlotWriterFunc adapts a synchronous test callback to the queue log writer.
type pushSlotWriterFunc func([]byte) (int, error)

// Write calls the callback with the bytes written to the queue log.
func (write pushSlotWriterFunc) Write(p []byte) (int, error) {
	return write(p)
}

// holdPushSlotForTest takes a slot and registers its idempotent release with the test.
func holdPushSlotForTest(t *testing.T) func() error {
	t.Helper()
	release, err := WaitPushSlot(t.Context(), time.Second, time.Millisecond, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	releaseOnce := sync.OnceValue(release)
	t.Cleanup(func() {
		if err := releaseOnce(); err != nil {
			t.Error(err)
		}
	})
	return releaseOnce
}

// TestReview2044KilledFixtureSharesParentQueue proves the parent is blocked until SIGKILL frees the child's slot.
func TestReview2044KilledFixtureSharesParentQueue(t *testing.T) {
	dir := pushSlotTestDir(t)
	kill := sync.OnceFunc(startPushSlotHolderSubprocess(t, dir))
	t.Cleanup(kill)
	release, err := WaitPushSlot(t.Context(), 100*time.Millisecond, 10*time.Millisecond, io.Discard)
	if release != nil {
		t.Fatalf("parent acquired while child held the slot: error %v, release %v", err, release())
	}
	if !errors.Is(err, ErrPushSlotHeld) {
		t.Fatalf("parent wait error = %v, want ErrPushSlotHeld", err)
	}
	kill()
	release, err = WaitPushSlot(t.Context(), 5*time.Second, 50*time.Millisecond, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	assertPushSlotEmpty(t)
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
			holdPushSlotEnv+"=1", childPushSlotBaseEnv+"="+runtimeDir, self, "-test.run=^TestPushSlotSubprocessHolder$", "-test.count=1")
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
	base := os.Getenv(childPushSlotBaseEnv)
	if base == "" {
		t.Fatal("missing shared push slot fixture directory")
	}
	t.Setenv(pushSlotTestBaseEnv, base)
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

// TestPushSlot_Boundary_LeaseDirMatchesLayout proves push slot uses the uid-scoped lease tree.
func TestPushSlot_Boundary_LeaseDirMatchesLayout(t *testing.T) {
	runtimeDir := pushSlotTestDir(t)
	want := filepath.Join(runtimeDir, pushSlotQueueDir)
	got, err := pushSlotLeaseDir()
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

// pushSlotTestDir points the push-slot runtime base at a fresh temporary folder (PushSlotTestBase).
func pushSlotTestDir(t *testing.T) string {
	t.Helper()
	return PushSlotTestBase(t)
}

// assertPushSlotEmpty fails the test when a push slot lease file is still present.
func assertPushSlotEmpty(t *testing.T) {
	t.Helper()
	dir, err := pushSlotLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(entries) && i < maxExecutorLeaseDirEntries; i++ {
		name := entries[i].Name()
		if name != pushSlotHolderName && filepath.Ext(name) == ".lock" {
			t.Fatalf("leftover push slot lease %s", name)
		}
	}
}
