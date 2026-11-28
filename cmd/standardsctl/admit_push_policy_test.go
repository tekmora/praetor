// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/admission"
	"github.com/cordanaLLM/praetor/internal/sentinel"
)

// TestReview2044RemotePolicyUsesExecutorHeadroom keeps a nearly full remote swap pool held.
func TestReview2044RemotePolicyUsesExecutorHeadroom(t *testing.T) {
	admitStubTools(t)
	admission.PushSlotTestBase(t)
	withAdmitHostStatsReader(t, func() (sentinel.HostStats, error) {
		return sentinel.HostStats{RAMTotalBytes: 8 * gib, SwapMeasured: true}, nil
	})
	t.Setenv(admitExecutorEnv, "")
	admitFixture{root: t.TempDir()}.inventory(t, "adequate")
	bin := filepath.SplitList(os.Getenv("PATH"))[0]
	writeAdmitExecutable(t, bin, "ssh", strings.Replace(admitFakeSSH, "SwapFree: 33554432", "SwapFree: 1048576", 1))
	writeAdmitExecutable(t, bin, "git", "#!/bin/sh\necho 'executor admitted unexpectedly' >&2\nexit 9\n")
	_, log, code := runAdmitCaptured(t, "--class", "push", "--wait", "250ms", "--poll", "100ms", "--", "true")
	if code != 75 || !strings.Contains(log, "adequate held: swap free 1.0 GiB < 15.0 GiB") {
		t.Fatalf("admission with low executor swap: exit %d, %s", code, log)
	}
}

const gib = 1 << 30

// pushPolicyStubHostStats is a measured no-swap host with ample memory and zero load.
func pushPolicyStubHostStats() sentinel.HostStats {
	return sentinel.HostStats{
		RAMTotalBytes: 64 * gib, RAMFreeBytes: 32 * gib,
		SwapMeasured: true, SwapTotalBytes: 0, SwapFreeBytes: 0,
		CPULoadMeasured: true, CPULoad1Min: 0,
	}
}

// withAdmitHostStatsReader swaps admitHostStatsReader for one test and restores it on cleanup.
func withAdmitHostStatsReader(t *testing.T, read func() (sentinel.HostStats, error)) {
	t.Helper()
	prev := admitHostStatsReader
	admitHostStatsReader = read
	t.Cleanup(func() { admitHostStatsReader = prev })
}

// Positive: push class caps swap to zero on a host sample without swap; other classes keep parsed defaults.
func TestApplyPushHostPolicy_Positive_NoSwapHostCapped(t *testing.T) {
	stats := sentinel.HostStats{RAMTotalBytes: 64 * gib, SwapMeasured: true, SwapTotalBytes: 0}
	base := admission.DefaultPolicy()
	got := applyPushHostPolicy(base, stats, false, false, true)
	if got.MinSwapFreeBytes != 0 {
		t.Fatalf("swap cap: got %d want 0", got.MinSwapFreeBytes)
	}
	wantAvail := admission.HostCappedPolicy(stats).MinAvailableBytes
	if got.MinAvailableBytes != wantAvail {
		t.Fatalf("memory cap: got %d want %d", got.MinAvailableBytes, wantAvail)
	}
	if resolveAdmitPolicy(admitOptions{policy: base}) != base {
		t.Fatal("non-push class must not cap policy")
	}
}

// Negative: an explicit swap threshold keeps the fleet bound on a host without swap.
func TestApplyPushHostPolicy_Negative_ExplicitSwapUnchanged(t *testing.T) {
	stats := sentinel.HostStats{RAMTotalBytes: 64 * gib, SwapMeasured: true, SwapTotalBytes: 0, SwapFreeBytes: 0}
	explicit := uint64(15 * gib)
	base := admission.Policy{MinAvailableBytes: 0, MinSwapFreeBytes: explicit, MaxLoad1: 0}
	got := applyPushHostPolicy(base, stats, true, true, false)
	if got.MinSwapFreeBytes != explicit {
		t.Fatalf("explicit swap: got %d want %d", got.MinSwapFreeBytes, explicit)
	}
	verdict := admission.Judge(stats, got)
	if verdict.Admit {
		t.Fatalf("explicit 15 GiB swap on no-swap host must refuse: %+v", verdict)
	}
}

// Negative: a host read error keeps fleet defaults and names the missing host cap on stderr.
func TestResolveAdmitPolicy_Negative_HostReaderError(t *testing.T) {
	withAdmitHostStatsReader(t, func() (sentinel.HostStats, error) {
		return sentinel.HostStats{}, errors.New("stub host read failed")
	})
	base := admission.DefaultPolicy()
	opts := admitOptions{admitClass: admitClassPush, policy: base}
	stderr, err := captureStderr(t, func() error {
		got := resolveAdmitPolicy(opts)
		if got != base {
			t.Fatalf("fleet default policy unchanged: got %+v want %+v", got, base)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "host-capped thresholds not applied") {
		t.Fatalf("stderr must name missing host cap: %q", stderr)
	}
}

// Boundary: push class on a stubbed no-swap host admits; explicit swap and non-push refuse on the same sample.
func TestRunAdmit_PushClass_Boundary_NoSwapHostAdmits_3D(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("push slot leases require Unix advisory file locks")
	}
	stub := pushPolicyStubHostStats()
	withAdmitHostStatsReader(t, func() (sentinel.HostStats, error) { return stub, nil })
	needShell(t)
	admitStubTools(t)
	admission.PushSlotTestBase(t)
	admitPushClassBoundaryPushAdmits(t, stub)
	admitPushClassBoundaryExplicitSwapRefuses(t, stub)
	admitPushClassBoundaryNonPushUnchanged(t, stub)
}

// admitPushClassBoundaryPushAdmits checks capped push class on the stub admits and runAdmit succeeds.
func admitPushClassBoundaryPushAdmits(t *testing.T, stub sentinel.HostStats) {
	t.Helper()
	pushOpts, err := parseAdmit([]string{"--class", "push", "--local", "--min-available-gib", "0", "--max-load", "0", "--", "true"})
	if err != nil {
		t.Fatal(err)
	}
	pushPolicy := resolveAdmitPolicy(pushOpts)
	if pushPolicy.MinSwapFreeBytes != 0 {
		t.Fatalf("implicit swap cap on stub: got %d want 0", pushPolicy.MinSwapFreeBytes)
	}
	if verdict := admission.Judge(stub, pushPolicy); !verdict.Admit {
		t.Fatalf("push policy must admit on stub: %+v", verdict)
	}
	if err := runAdmit([]string{"--class", "push", "--local", "--min-available-gib", "0", "--max-load", "0",
		"--wait", "10s", "--poll", "50ms", "--", "sh", "-c", "exit 0"}); err != nil {
		t.Fatalf("push on stub-capped no-swap policy: %v", err)
	}
}

// admitPushClassBoundaryExplicitSwapRefuses keeps an explicit swap threshold and refuses on the no-swap stub.
func admitPushClassBoundaryExplicitSwapRefuses(t *testing.T, stub sentinel.HostStats) {
	t.Helper()
	explicitOpts, err := parseAdmit([]string{"--class", "push", "--local", "--min-available-gib", "0",
		"--min-swap-free-gib", "15", "--max-load", "0", "--", "true"})
	if err != nil {
		t.Fatal(err)
	}
	explicitPolicy := resolveAdmitPolicy(explicitOpts)
	if explicitPolicy.MinSwapFreeBytes != 15*gib {
		t.Fatalf("explicit swap kept: got %d", explicitPolicy.MinSwapFreeBytes)
	}
	if verdict := admission.Judge(stub, explicitPolicy); verdict.Admit {
		t.Fatalf("explicit 15 GiB swap on no-swap stub must refuse: %+v", verdict)
	}
}

// admitPushClassBoundaryNonPushUnchanged keeps default non-push policy and refuses on the no-swap stub.
func admitPushClassBoundaryNonPushUnchanged(t *testing.T, stub sentinel.HostStats) {
	t.Helper()
	plainOpts, err := parseAdmit([]string{"--local", "--", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if plainOpts.policy.MinSwapFreeBytes != admission.DefaultPolicy().MinSwapFreeBytes {
		t.Fatalf("non-push keeps default swap %+v", plainOpts.policy)
	}
	if resolveAdmitPolicy(plainOpts) != plainOpts.policy {
		t.Fatal("non-push resolve must not cap policy")
	}
	if verdict := admission.Judge(stub, plainOpts.policy); verdict.Admit {
		t.Fatalf("default swap threshold on no-swap stub must refuse: %+v", verdict)
	}
}
