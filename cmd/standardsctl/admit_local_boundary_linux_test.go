// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

// TestLocalBuilderCap_MixedLaunchEnvironments holds three independent CLIs with XDG
// set, then attempts a fourth admission with XDG absent and a different temporary root.
func TestLocalBuilderCap_MixedLaunchEnvironments(t *testing.T) {
	localBuilderFixture(t, "3")
	// The three child CLIs must see an XDG path distinct from the UID-derived path.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	launch, err := util.WithCommandEnvironment(rootContext(), admitFixtureEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	previous := rootCtx
	rootCtx = launch
	defer func() { rootCtx = previous }()
	defer holdLocalBuilder(t)()
	defer holdLocalBuilder(t)()
	defer holdLocalBuilder(t)()
	t.Setenv("TMPDIR", t.TempDir())
	if err := os.Unsetenv("XDG_RUNTIME_DIR"); err != nil {
		t.Fatal(err)
	}
	assertLocalQueueFull(t, localBusyMessage)
}

// assertLocalQueueFull requires the waiter to report occupancy and withhold the step.
func assertLocalQueueFull(t *testing.T, reason string) {
	t.Helper()
	start := time.Now()
	out, log, code := runAdmitCaptured(t, localBuilderArgs("500ms", "sh", "-c", "echo ran")...)
	if code == 0 || out != "" || !strings.Contains(log, "admission wait") || !strings.Contains(log, reason) {
		t.Fatalf("local queue: exit %d, stdout %q, stderr %q", code, out, log)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("refused before wait expired: %s", elapsed)
	}
}

// lockLocalFixturePeer takes the temporary flock that a stale-file scan would hold.
func lockLocalFixturePeer(t *testing.T, path string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	unlock, busy, lockErr := util.LockPrivateFile(root, filepath.Base(path), os.O_RDONLY, "local peer fixture")
	if unlock != nil {
		t.Cleanup(func() {
			if err := unlock(); err != nil {
				t.Error(err)
			}
		})
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if lockErr != nil || busy || unlock == nil {
		t.Fatalf("fixture lock: busy %t, err %v", busy, lockErr)
	}
}

// TestLocalBuilderCap_RecycledAncestor plants an old process identity under the
// current parent's PID and holds its flock from an unrelated process (the test).
func TestLocalBuilderCap_RecycledAncestor(t *testing.T) {
	localBuilderFixture(t, "1")
	owner := strconv.Itoa(os.Getppid())
	stale := writeFixtureFile(t, os.Getenv("XDG_RUNTIME_DIR"),
		"praetor-admit-leases/local/"+owner+"-old.lock", owner+" 18446744073709551615")
	lockLocalFixturePeer(t, stale)
	t.Setenv(localMarkerSetting, owner)
	assertLocalQueueFull(t, "admit: local builders 1 of 1 busy")
}

// TestLocalBuilderCap_ScanBoundary exercises the final scan slot with every flock
// stale, then with every flock held. Both fixtures start with exactly 256 files.
func TestLocalBuilderCap_ScanBoundary(t *testing.T) {
	for _, state := range []string{"stale", "held"} {
		t.Run(state, func(t *testing.T) {
			localBuilderFixture(t, "256")
			dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "praetor-admit-leases", "local")
			for i := range 256 {
				path := writeFixtureFile(t, dir, strconv.Itoa(i)+"-peer.lock", "")
				if state == "held" {
					lockLocalFixturePeer(t, path)
				}
			}
			if state == "held" {
				assertLocalQueueFull(t, "admit: local builders 256 of 256 busy")
				return
			}
			out, log, code := runAdmitCaptured(t, localBuilderArgs("2s", "sh", "-c", "echo ran")...)
			if code != 0 || out != "ran\n" {
				t.Fatalf("reclaim: exit %d, stdout %q, stderr %q", code, out, log)
			}
			assertNoAdmitLeaseFiles(t, dir)
		})
	}
}

// TestLocalBuilderCap_UnsupportedLimit rejects the first value beyond the scan.
func TestLocalBuilderCap_UnsupportedLimit(t *testing.T) {
	t.Setenv(localLimitSetting, "257")
	for _, args := range [][]string{{"--", "true"}, {"--max-local-builders=257", "--", "true"}} {
		if _, err := parseAdmit(args); err == nil || !strings.Contains(err.Error(), "256") {
			t.Errorf("cap above scan bound accepted or unexplained: %v", err)
		}
	}
	if _, err := parseAdmit([]string{"--max-local-builders=256", "--", "true"}); err != nil {
		t.Fatalf("maximum cap: %v", err)
	}
}
