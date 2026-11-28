// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/admission"
	"github.com/cordanaLLM/praetor/internal/util"
)

// These tests use only the CLI contract so the same file can be planted on the parent commit.
const localLimitSetting = "PRAETOR_ADMIT_MAX_LOCAL_BUILDERS"
const localMarkerSetting = "PRAETOR_ADMIT_LOCAL_LEASE_PID"
const localBusyMessage = "admit: local builders 3 of 3 busy"

// TestLocalBuilderFixtureCLI dispatches the child test binary's arguments as a real admit.
func TestLocalBuilderFixtureCLI(t *testing.T) {
	if args := flag.Args(); len(args) > 0 && args[0] == "fixture-local-builder" {
		fixtureTmp := os.Getenv("ADMIT_FIXTURE_TEMP_ROOT")
		if fixtureTmp == "" {
			t.Fatal("missing fixture filesystem root")
		}
		rootCtx = admission.WithLocalLeaseTempRoot(t.Context(), fixtureTmp)
		if err := runAdmit(args[1:]); err != nil {
			t.Fatal(err)
		}
	}
}

// localBuilderFixture isolates the runtime directory, scope launcher and inherited settings.
func localBuilderFixture(t *testing.T, limit string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("local admission requires Linux")
	}
	t.Setenv(localLimitSetting, limit)
	if limit == "" {
		if err := os.Unsetenv(localLimitSetting); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(localMarkerSetting, "")
	t.Setenv(admitExecutorEnv, "")
	t.Setenv(admitExecutorsEnv, "")
	admitStubTools(t)
}

// localBuilderArgs bypasses host thresholds in the fixture and bounds both wait and runtime.
func localBuilderArgs(wait string, argv ...string) []string {
	return append([]string{"--local", "--min-available-gib=0", "--min-swap-free-gib=0", "--max-load=0",
		"--poll=15ms", "--wait=" + wait, "--timeout=30s", "--"}, argv...)
}

// localBuilderCLI returns the test binary and fixed dispatch arguments for a child admission.
func localBuilderCLI(t *testing.T, args []string) []string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{self, "-test.run=^TestLocalBuilderFixtureCLI$", "--", "fixture-local-builder"}, args...)
}

// localBuilderOutput signals once the step or waiter reaches the requested line.
type localBuilderOutput struct {
	log   bytes.Buffer
	match string
	seen  chan struct{}
	once  sync.Once
}

// Write retains the subprocess output across chunk boundaries before notifying the test.
func (o *localBuilderOutput) Write(p []byte) (int, error) {
	n, err := o.log.Write(p)
	if bytes.Contains(o.log.Bytes(), []byte(o.match)) {
		o.once.Do(func() { close(o.seen) })
	}
	return n, err
}

// startLocalBuilder waits for readiness over the child's output and releases its stdin on demand.
func startLocalBuilder(t *testing.T, match string, argv ...string) func() {
	t.Helper()
	command := localBuilderCLI(t, localBuilderArgs("20s", argv...))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(rootContext(), 40*time.Second)
	output := &localBuilderOutput{match: match, seen: make(chan struct{})}
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = util.RunCommandPassthrough(ctx, "", command[0], reader, output, output, command[1:]...)
	}()
	stop := sync.OnceFunc(func() {
		defer cancel()
		closeErr := writer.Close()
		<-done
		if err := errors.Join(closeErr, runErr, reader.Close()); err != nil {
			t.Errorf("local builder: %v\n%s", err, output.log.String())
		}
	})
	t.Cleanup(stop)
	select {
	case <-output.seen:
	case <-done:
		t.Fatalf("builder exited before %q: %v\n%s", match, runErr, output.log.String())
	case <-ctx.Done():
		t.Fatalf("waiting for %q: %v", match, ctx.Err())
	}
	return stop
}

// holdLocalBuilder starts a CLI whose step owns its slot until the test closes stdin.
func holdLocalBuilder(t *testing.T) func() {
	t.Helper()
	return startLocalBuilder(t, "holding slot", "sh", "-ec", "echo 'holding slot'; cat >/dev/null")
}

// TestLocalBuilderCap_FourthRefusedAndWaiterWakes exercises four independent local CLI processes.
func TestLocalBuilderCap_FourthRefusedAndWaiterWakes(t *testing.T) {
	localBuilderFixture(t, "")
	first := holdLocalBuilder(t)
	defer first()
	defer holdLocalBuilder(t)()
	defer holdLocalBuilder(t)()
	args := localBuilderArgs("500ms", "sh", "-c", "echo fourth-ran")
	start := time.Now()
	out, log, code := runAdmitCaptured(t, args...)
	if code == 0 || out != "" || !strings.Contains(log, localBusyMessage) || !strings.Contains(log, "admission wait") {
		t.Fatalf("fourth admit: exit %d, stdout %q, stderr %q", code, out, log)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("refused before the wait budget expired: %s, stderr %q", elapsed, log)
	}
	dir := t.TempDir()
	waiter := startLocalBuilder(t, localBusyMessage, "sh", "-ec", `echo admitted > "$1"`, "waiter", filepath.Join(dir, "ran"))
	first()
	waiter()
	if got := readFixtureFile(t, dir, "ran"); got != "admitted\n" {
		t.Fatalf("waiter step output = %q", got)
	}
}

// TestLocalBuilderCap_CopiedMarker makes an unrelated caller try the actual holder's marker.
func TestLocalBuilderCap_CopiedMarker(t *testing.T) {
	localBuilderFixture(t, "1")
	defer holdLocalBuilder(t)()
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "praetor-admit-leases", "local")
	files, err := filepath.Glob(filepath.Join(dir, "*.lock"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wanted one live lease: %v, %v", files, err)
	}
	owner, _, _ := strings.Cut(filepath.Base(files[0]), "-")
	t.Setenv(localMarkerSetting, owner)
	out, log, code := runAdmitCaptured(t, localBuilderArgs("1s", "sh", "-c", "echo unrelated-ran")...)
	if code == 0 || out != "" || !strings.Contains(log, "admit: local builders 1 of 1 busy") {
		t.Fatalf("copied marker: exit %d, stdout %q, stderr %q", code, out, log)
	}
}

// TestLocalBuilderCap_Nested reads the number of leases from inside a nested step at cap one.
func TestLocalBuilderCap_Nested(t *testing.T) {
	localBuilderFixture(t, "1")
	// The fixture captured its explicit child environment before this parent-only value.
	t.Setenv("ADMIT_FIXTURE_PARENT_ONLY", "parent")
	const inspect = `test -z "${ADMIT_FIXTURE_PARENT_ONLY:-}"
test -n "$PRAETOR_ADMIT_LOCAL_LEASE_PID"
set -- "$XDG_RUNTIME_DIR"/praetor-admit-leases/local/*.lock
test "$#" -eq 1 && test -f "$1" && echo nested-one`
	inner := localBuilderArgs("3s", "sh", "-ec", inspect)
	command := localBuilderCLI(t, inner[1:]) // The outer --local also covers a plain nested admit.
	// Keep a judge shell between the owner and the nested CLI.
	script := append([]string{"sh", "-ec", `"$@"; echo judge-done`, "judge"}, command...)
	out, log, code := runAdmitCaptured(t, localBuilderArgs("2s", script...)...)
	if code != 0 || !strings.Contains(out, "nested-one") {
		t.Fatalf("nested admit: exit %d, stdout %q, stderr %q", code, out, log)
	}
	if strings.Count(log, "planted scope limits") != 1 {
		t.Fatalf("expected exactly one stub scope: %s", log)
	}
}

// abandonedLocalLease keeps the fixture's locked descriptor reachable until process exit.
var abandonedLocalLease func() error

// TestLocalBuilderOrphanFixture exits normally while holding a lock in the fixture directory.
func TestLocalBuilderOrphanFixture(t *testing.T) {
	if flag.Arg(0) != "abandon-fixture-lease" {
		return
	}
	root, err := os.OpenRoot(flag.Arg(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	var busy bool
	abandonedLocalLease, busy, err = util.LockPrivateFile(root, flag.Arg(2), os.O_RDWR, "stale local fixture")
	if err != nil || busy || abandonedLocalLease == nil {
		t.Fatalf("hold orphan fixture lease: %v, busy %t", err, busy)
	}
}

// TestLocalBuilderCap_Stale proves a dead holder's unlocked file cannot occupy the only slot.
func TestLocalBuilderCap_Stale(t *testing.T) {
	localBuilderFixture(t, "1")
	stale := writeFixtureFile(t, os.Getenv("XDG_RUNTIME_DIR"), "praetor-admit-leases/local/999999-stale.lock", "")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(rootContext(), 20*time.Second)
	defer cancel()
	if out, err := util.RunCommandBytes(ctx, "", self, 4096, "-test.run=^TestLocalBuilderOrphanFixture$", "--",
		"abandon-fixture-lease", filepath.Dir(stale), filepath.Base(stale)); err != nil {
		t.Fatalf("holder exit: %v, %s%s", err, out.Stdout, out.Stderr)
	}
	out, log, code := runAdmitCaptured(t, localBuilderArgs("2s", "sh", "-c", "echo ran")...)
	if code != 0 || out != "ran\n" {
		t.Fatalf("stale lease: exit %d, stdout %q, stderr %q", code, out, log)
	}
	assertNoAdmitLeaseFiles(t, filepath.Dir(stale))
}

// TestLocalBuilderCap_Invalid checks the flag, the environment default and their precedence.
func TestLocalBuilderCap_Invalid(t *testing.T) {
	for _, bad := range []string{"0", "-1", "many", ""} {
		t.Setenv(localLimitSetting, bad)
		if _, err := parseAdmit([]string{"--", "stub"}); err == nil || !strings.Contains(err.Error(), "positive integer") {
			t.Errorf("environment cap %q: %v", bad, err)
		}
		if _, err := parseAdmit([]string{"--max-local-builders=1", "--", "stub"}); err != nil {
			t.Errorf("explicit positive cap over %q: %v", bad, err)
		}
		t.Setenv(localLimitSetting, "3")
		if _, err := parseAdmit([]string{"--max-local-builders=" + bad, "--", "stub"}); err == nil || !strings.Contains(err.Error(), "positive integer") {
			t.Errorf("flag cap %q: %v", bad, err)
		}
	}
}
