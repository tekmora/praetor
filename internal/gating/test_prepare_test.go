// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package gating

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/lockdown"
	"github.com/cordanaLLM/praetor/internal/testsupport"
)

// stubPrepSource is a cross-platform Go executable used as a gate.test_prepare command in fixtures.
const stubPrepSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func logCall(wd string) {
	logPath := os.Getenv("STUB_PREP_LOG")
	if logPath == "" {
		return
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	fmt.Fprintln(f, wd+"\t"+strings.Join(os.Args[1:], "|"))
	if f.Close() != nil {
		os.Exit(3)
	}
}

func main() {
	wd, err := os.Getwd()
	if err != nil || len(os.Args) < 2 {
		os.Exit(3)
	}
	logCall(wd)
	switch os.Args[1] {
	case "write":
		target := filepath.Join(wd, filepath.FromSlash(os.Args[2]))
		if os.MkdirAll(filepath.Dir(target), 0o750) != nil {
			os.Exit(3)
		}
		if os.WriteFile(target, []byte(os.Args[3]), 0o600) != nil {
			os.Exit(3)
		}
	case "check":
		target := filepath.Join(wd, filepath.FromSlash(os.Args[2]))
		if _, statErr := os.Stat(target); statErr != nil {
			fmt.Fprintf(os.Stderr, "missing %s\n", os.Args[2])
			os.Exit(2)
		}
	case "fail":
		code, _ := strconv.Atoi(os.Args[2])
		out := os.Args[3]
		if len(os.Args) > 4 && os.Args[4] == "huge" {
			out += " " + strings.Repeat("x", 5000)
		}
		fmt.Println(out)
		os.Exit(code)
	}
}
`

// stubWrapperSource is a cross-platform Go executable standing in for gate.test_wrapper (e.g. xvfb-run).
// It records its full received argv to STUB_WRAPPER_LOG, sets STUB_WRAPPED=1, and execs os.Args[3:].
const stubWrapperSource = `package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	wd, err := os.Getwd()
	if err != nil || len(os.Args) < 4 {
		os.Exit(4)
	}
	if logPath := os.Getenv("STUB_WRAPPER_LOG"); logPath != "" {
		f, openErr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if openErr != nil {
			os.Exit(4)
		}
		fmt.Fprintln(f, wd+"\t"+strings.Join(os.Args[1:], "|"))
		if f.Close() != nil {
			os.Exit(4)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[3], os.Args[4:]...)
	cmd.Dir = wd
	cmd.Env = append(os.Environ(), "STUB_WRAPPED=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, runErr)
		os.Exit(5)
	}
}
`

// stubCargoRequireSource stands in for cargo and fails test/clippy unless REQUIRE_WORKTREE_FILE exists in wd.
const stubCargoRequireSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	wd, err := os.Getwd()
	if err != nil || len(os.Args) < 2 {
		os.Exit(3)
	}
	if logPath := os.Getenv("FAKE_CARGO_LOG"); logPath != "" {
		f, openErr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if openErr != nil {
			os.Exit(3)
		}
		fmt.Fprintln(f, wd+"\t"+strings.Join(os.Args[1:], "|"))
		if f.Close() != nil {
			os.Exit(3)
		}
	}
	sub := os.Args[1]
	if (sub == "test" || sub == "clippy") && os.Getenv("REQUIRE_WORKTREE_FILE") != "" {
		req := filepath.FromSlash(os.Getenv("REQUIRE_WORKTREE_FILE"))
		if _, statErr := os.Stat(filepath.Join(wd, req)); statErr != nil {
			fmt.Printf("error: build.rs missing %s in %s\n", req, wd)
			os.Exit(101)
		}
	}
	if (sub == "test" || sub == "clippy") && os.Getenv("REQUIRE_WRAPPED") == "1" && os.Getenv("STUB_WRAPPED") != "1" {
		fmt.Println("error: suite ran without test_wrapper")
		os.Exit(101)
	}
}
`

// stubGoRequireSource stands in for go so Go test-stage fixtures run hermetically on every OS without cgo.
const stubGoRequireSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	wd, err := os.Getwd()
	if err != nil || len(os.Args) < 2 {
		os.Exit(3)
	}
	if os.Args[1] == "env" && len(os.Args) == 3 {
		if os.Args[2] == "CGO_ENABLED" {
			fmt.Println("1")
			return
		}
		if os.Args[2] == "CC" {
			fmt.Println("stub-cc")
			return
		}
	}
	if os.Args[1] == "list" {
		fmt.Println("example.test/fx")
		return
	}
	if logPath := os.Getenv("FAKE_GO_LOG"); logPath != "" {
		f, openErr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if openErr != nil {
			os.Exit(3)
		}
		fmt.Fprintln(f, wd+"\t"+strings.Join(os.Args[1:], "|"))
		if f.Close() != nil {
			os.Exit(3)
		}
	}
	if os.Args[1] == "test" && os.Getenv("REQUIRE_WORKTREE_FILE") != "" {
		req := filepath.FromSlash(os.Getenv("REQUIRE_WORKTREE_FILE"))
		if _, statErr := os.Stat(filepath.Join(wd, req)); statErr != nil {
			fmt.Printf("FAIL: missing prepared artefact %s\n", req)
			os.Exit(1)
		}
	}
	if os.Args[1] == "test" && os.Getenv("REQUIRE_WRAPPED") == "1" && os.Getenv("STUB_WRAPPED") != "1" {
		fmt.Println("FAIL: go test ran without test_wrapper")
		os.Exit(1)
	}
}
`

// prepShimLogs holds the temporary log file paths written by the fixture shims.
type prepShimLogs struct {
	prep    string
	wrapper string
	cargo   string
	golang  string
}

// installPrepShims builds cross-platform stand-ins for stub-prep, stub-wrapper, cargo, cargo-audit,
// go, and stub-cc onto PATH and configures hermetic stage environment variables.
func installPrepShims(t *testing.T) prepShimLogs {
	t.Helper()
	bin := t.TempDir()
	testsupport.BuildExecutable(t, bin, "stub-prep", stubPrepSource)
	testsupport.BuildExecutable(t, bin, "stub-wrapper", stubWrapperSource)
	testsupport.BuildExecutable(t, bin, "cargo", stubCargoRequireSource)
	testsupport.BuildExecutable(t, bin, "cargo-audit", "package main\n\nfunc main() {}\n")
	testsupport.BuildExecutable(t, bin, "go", stubGoRequireSource)
	testsupport.BuildExecutable(t, bin, "stub-cc", "package main\n\nfunc main() {}\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(cargoTargetDirEnv, "")
	t.Setenv(TestStageTimeoutEnv, "")
	t.Setenv(GateScopeEnv, "off")
	t.Setenv(GateAdmissionEnv, "off")
	t.Setenv(DevcontainerEnv, "off")
	t.Setenv("CI", "true")
	t.Setenv("REQUIRE_WORKTREE_FILE", "")
	t.Setenv("REQUIRE_WRAPPED", "")
	logDir := t.TempDir()
	logs := prepShimLogs{
		prep:    filepath.Join(logDir, "prep.log"),
		wrapper: filepath.Join(logDir, "wrapper.log"),
		cargo:   filepath.Join(logDir, "cargo.log"),
		golang:  filepath.Join(logDir, "go.log"),
	}
	t.Setenv("STUB_PREP_LOG", logs.prep)
	t.Setenv("STUB_WRAPPER_LOG", logs.wrapper)
	t.Setenv("FAKE_CARGO_LOG", logs.cargo)
	t.Setenv("FAKE_GO_LOG", logs.golang)
	return logs
}

// newCargoPrepareConfig commits a Cargo workspace with manifestYAML and returns a production stageConfig.
func newCargoPrepareConfig(t *testing.T, manifestYAML string) *stageConfig {
	t.Helper()
	repo := newHermeticGitRepo(t)
	commitFile(t, repo, "Cargo.toml", "[workspace]\nmembers = []\nresolver = \"3\"\n")
	commitFile(t, repo, CargoLockFile, "version = 4\n")
	commitFile(t, repo, ".standards.lock", "version: 1\n")
	commitFile(t, repo, ".standards.yaml", manifestYAML)
	rep := &PipelineReport{
		Repository:    "example/zig-rust",
		CommitSHA:     headOf(t, repo),
		WorktreeClean: true,
		Stages:        make([]StageResult, 0, maxStages),
	}
	cfg := newStageConfig(repo, false, rep)
	cfg.inspectTree = cleanTree(rep)
	return cfg
}

// newGoPrepareConfig commits a Go module with manifestYAML and returns a production stageConfig.
func newGoPrepareConfig(t *testing.T, manifestYAML string) *stageConfig {
	t.Helper()
	repo := newHermeticGitRepo(t)
	commitFile(t, repo, "go.mod", "module example.test/fx\n")
	commitFile(t, repo, "fx.go", "package fx\n")
	commitFile(t, repo, ".standards.lock", "version: 1\n")
	commitFile(t, repo, ".standards.yaml", manifestYAML)
	rep := &PipelineReport{
		Repository:    "example/zig-go",
		CommitSHA:     headOf(t, repo),
		WorktreeClean: true,
		Stages:        make([]StageResult, 0, maxStages),
	}
	cfg := newStageConfig(repo, false, rep)
	cfg.inspectTree = cleanTree(rep)
	return cfg
}

// readShimLines returns trimmed non-empty lines from path, or nil when path was never created.
func readShimLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- path is created under t.TempDir() by installPrepShims
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// runBoundedTestStage executes only the test stage under an explicit test timeout.
func runBoundedTestStage(t *testing.T, cfg *stageConfig) (StageResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	err := executeStage(ctx, stage{stageTests, runTestStage}, cfg)
	return cfg.rep.Stages[len(cfg.rep.Stages)-1], err
}

// TestTestPrepare_Positive_FixtureRedWithoutPrepareAndGreenWithPrepare covers case 5(a):
// Cargo and Go fixtures whose suites require zig-out/lib/libnative.a fail without gate.test_prepare
// and pass (minting a verified receipt for Cargo) when gate.test_prepare creates it in the worktree.
func TestTestPrepare_Positive_FixtureRedWithoutPrepareAndGreenWithPrepare(t *testing.T) {
	pub := sandboxReceiptKey(t)
	logs := installPrepShims(t)
	const fixturePath = "zig-out/lib/libnative.a"
	t.Setenv("REQUIRE_WORKTREE_FILE", fixturePath)

	unpreparedCargo := newCargoPrepareConfig(t, "version: 1\n")
	if err := runThroughReceipt(t, unpreparedCargo); err == nil || !strings.Contains(err.Error(), filepath.FromSlash(fixturePath)) {
		t.Fatalf("unprepared Cargo fixture must fail naming missing artefact, got %v", err)
	}

	declaredYAML := "version: 1\ngate:\n  test_prepare:\n    - [\"stub-prep\", \"write\", \"zig-out/lib/libnative.a\", \"built\"]\n"
	preparedCargo := newCargoPrepareConfig(t, declaredYAML)
	if err := runThroughReceipt(t, preparedCargo); err != nil {
		t.Fatalf("prepared Cargo fixture failed: %v (%+v)", err, preparedCargo.rep.Stages)
	}
	verifyPreparedCargoOutcome(t, preparedCargo, pub, logs.prep)

	unpreparedGo := newGoPrepareConfig(t, "version: 1\n")
	if res, err := runBoundedTestStage(t, unpreparedGo); err == nil || res.Status != StageFailed {
		t.Fatalf("unprepared Go fixture must fail, got %+v (%v)", res, err)
	}
	verifyPreparedGoOutcome(t, newGoPrepareConfig(t, declaredYAML))
}

// verifyPreparedGoOutcome runs a prepared Go fixture and verifies pass status, message, and clean checkout.
func verifyPreparedGoOutcome(t *testing.T, cfg *stageConfig) {
	t.Helper()
	res, err := runBoundedTestStage(t, cfg)
	if err != nil || res.Status != StagePassed || !strings.Contains(res.Message, "test_prepare ran 1 command") {
		t.Fatalf("prepared Go fixture = %+v (%v), want passed naming preparation", res, err)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.repoDir, "zig-out")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("test_prepare wrote into checkout instead of isolated worktree: %v", statErr)
	}
}

// verifyPreparedCargoOutcome asserts receipt verification, worktree confinement, and stage output note.
func verifyPreparedCargoOutcome(t *testing.T, cfg *stageConfig, pub ed25519.PublicKey, prepLog string) {
	t.Helper()
	rf, err := lockdown.LoadReceiptFile(filepath.Join(cfg.repoDir, ReceiptFileName))
	if err != nil {
		t.Fatalf("LoadReceiptFile: %v", err)
	}
	if err := lockdown.VerifyPinnedReceiptFile(rf, pub); err != nil {
		t.Fatalf("VerifyPinnedReceiptFile: %v", err)
	}
	if !strings.Contains(rf.GateOutput, "test_prepare ran 1 command") {
		t.Errorf("signed GateOutput lacks preparation note:\n%s", rf.GateOutput)
	}
	lines := readShimLines(t, prepLog)
	if len(lines) != 1 || !strings.Contains(filepath.ToSlash(lines[0]), "/worktrees/") {
		t.Errorf("expected 1 worktree prepare run, got %q", lines)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.repoDir, "zig-out")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("test_prepare dirtied the source checkout: %v", statErr)
	}
}

// TestTestPrepare_Negative_FailingPrepareStopsStageAndNamesCommandExitAndExcerpt covers case 5(b):
// the first failing prepare command stops the stage before later prepare commands and suites,
// naming the joined argv, exit status, and bounded output excerpt.
func TestTestPrepare_Negative_FailingPrepareStopsStageAndNamesCommandExitAndExcerpt(t *testing.T) {
	manifestYAML := `version: 1
gate:
  test_prepare:
    - ["stub-prep", "fail", "7", "zig build failed: missing header", "huge"]
    - ["stub-prep", "write", "zig-out/second.txt", "never"]
`
	for _, kind := range []string{"cargo", "go"} {
		t.Run(kind, func(t *testing.T) {
			assertFailingPrepareStopsStage(t, kind, manifestYAML)
		})
	}
}

// assertFailingPrepareStopsStage runs the failing-prepare manifest for one suite kind and checks
// that the stage fails naming the command, exit status and excerpt, and that nothing ran after it.
func assertFailingPrepareStopsStage(t *testing.T, kind, manifestYAML string) {
	t.Helper()
	logs := installPrepShims(t)
	cfg := newCargoPrepareConfig(t, manifestYAML)
	suiteLog := logs.cargo
	if kind == "go" {
		cfg = newGoPrepareConfig(t, manifestYAML)
		suiteLog = logs.golang
	}
	res, err := runBoundedTestStage(t, cfg)
	if err == nil || res.Status != StageFailed {
		t.Fatalf("expected failed stage, got %+v (%v)", res, err)
	}
	for _, want := range []string{
		"stub-prep fail 7 zig build failed: missing header huge",
		"exit status 7",
		"zig build failed: missing header",
		"... [truncated]",
	} {
		if !strings.Contains(res.Message, want) {
			t.Errorf("stage message %q lacks %q", res.Message, want)
		}
	}
	if got := readShimLines(t, logs.prep); len(got) != 1 {
		t.Errorf("expected only first prepare command to run, got %q", got)
	}
	if got := readShimLines(t, suiteLog); len(got) != 0 {
		t.Errorf("suite ran after prepare failed: %q", got)
	}
}

// TestTestPrepare_Negative_CommandNotOnPathFailsByName covers case 5(c):
// a prepare command or wrapper command absent from PATH fails the stage by name (never skipped or passed).
func TestTestPrepare_Negative_CommandNotOnPathFailsByName(t *testing.T) {
	cases := []struct {
		name, yaml, missing string
	}{
		{
			name:    "missing prepare binary",
			yaml:    "version: 1\ngate:\n  test_prepare:\n    - [\"absent-zig-binary\", \"build\"]\n",
			missing: "absent-zig-binary",
		},
		{
			name:    "missing wrapper binary",
			yaml:    "version: 1\ngate:\n  test_wrapper: [\"absent-xvfb-wrapper\", \"-a\"]\n  test_prepare:\n    - [\"stub-prep\", \"write\", \"a.txt\", \"1\"]\n",
			missing: "absent-xvfb-wrapper",
		},
	}
	for i := 0; i < len(cases) && i < 8; i++ {
		tc := cases[i]
		for _, kind := range []string{"cargo", "go"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				assertMissingBinaryStageFailure(t, kind, tc.yaml, tc.missing)
			})
		}
	}
}

// TestHostToolchainHave checks explicit worktree paths with the real executable lookup.
func TestHostToolchainHave(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Base(testsupport.BuildExecutable(t, dir, "prep-tool", "package main\nfunc main() {}\n"))
	missing := testsupport.ExecutableName("missing-tool")
	cfg := stageConfig{lookPath: exec.LookPath}
	have := cfg.hostToolchain().have
	explicit := "." + string(filepath.Separator)
	if err := have(t.Context(), dir, explicit+present); err != nil {
		t.Fatalf("worktree command was not found: %v", err)
	}
	if err := have(t.Context(), dir, explicit+missing); !errors.Is(err, errNotOnPath) {
		t.Fatalf("missing worktree command: got %v, want errNotOnPath", err)
	}
}

// TestHostToolchainHaveInjectedLookup checks lookup names and error preservation.
func TestHostToolchainHaveInjectedLookup(t *testing.T) {
	dir := t.TempDir()
	present := testsupport.ExecutableName("prep-tool")
	explicit := "." + string(filepath.Separator)
	var calls []string
	lookupErr := errors.New("injected lookup failure")
	cfg := stageConfig{lookPath: func(name string) (string, error) {
		calls = append(calls, name)
		return "", lookupErr
	}}
	checked := cfg.hostToolchain().have
	bareNames := []string{"prep-tool"}
	if !os.IsPathSeparator('\\') {
		bareNames = append(bareNames, `prep\tool`)
	}
	for _, name := range bareNames {
		if err := checked(t.Context(), dir, name); !errors.Is(err, lookupErr) || !errors.Is(err, errNotOnPath) {
			t.Fatalf("lookup for %q did not preserve both errors: %v", name, err)
		}
	}
	if !slices.Equal(calls, bareNames) {
		t.Fatalf("lookup got %q, want unchanged bare names %q", calls, bareNames)
	}
	calls = nil
	if err := checked(t.Context(), ".", explicit+present); !errors.Is(err, lookupErr) || !errors.Is(err, errNotOnPath) {
		t.Fatalf("explicit lookup from dot did not preserve both errors: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("explicit lookup from dot: got %d calls, want one", len(calls))
	}
	if prefix, _ := filepath.Split(calls[0]); prefix == "" {
		t.Fatalf("explicit lookup from dot became a bare-name lookup: %q", calls[0])
	}
}

// TestHostToolchainHaveSymlinkParent checks that the filesystem resolves .. after a symlink.
func TestHostToolchainHaveSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix symlink traversal semantics")
	}
	dir := t.TempDir()
	parent, err := os.MkdirTemp(dir, "physical")
	if err != nil {
		t.Fatal(err)
	}
	subdir, err := os.MkdirTemp(parent, "subdir")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(subdir, filepath.Join(dir, "via")); err != nil {
		t.Fatal(err)
	}
	present := filepath.Base(testsupport.BuildExecutable(t, parent, "prep", "package main\nfunc main() {}\n"))
	cfg := stageConfig{lookPath: exec.LookPath}
	if err := cfg.hostToolchain().have(t.Context(), dir, "./via/../"+present); err != nil {
		t.Fatalf("command in the symlink target's parent was not found: %v", err)
	}
}

// assertMissingBinaryStageFailure runs kind's test stage and requires StageFailed naming missing on PATH.
func assertMissingBinaryStageFailure(t *testing.T, kind, manifestYAML, missing string) {
	t.Helper()
	logs := installPrepShims(t)
	cfg := newCargoPrepareConfig(t, manifestYAML)
	if kind == "go" {
		cfg = newGoPrepareConfig(t, manifestYAML)
	}
	res, err := runBoundedTestStage(t, cfg)
	if err == nil || res.Status != StageFailed {
		t.Fatalf("missing binary must fail (not skip/pass), got %+v (%v)", res, err)
	}
	if !strings.Contains(res.Message, missing) || !strings.Contains(res.Message, "not on PATH") {
		t.Errorf("message %q must name %q and 'not on PATH'", res.Message, missing)
	}
	if len(readShimLines(t, logs.cargo)) != 0 || len(readShimLines(t, logs.golang)) != 0 {
		t.Error("suite must not run when prepare/wrapper binary is absent")
	}
}

// TestTestPrepare_Positive_WrapperArgvPrefixed covers case 5(d):
// gate.test_wrapper prefixes every prepare command and every Cargo and Go suite command in order.
func TestTestPrepare_Positive_WrapperArgvPrefixed(t *testing.T) {
	fullYAML := "version: 1\ngate:\n  test_wrapper: [\"stub-wrapper\", \"--display\", \":99\"]\n  test_prepare:\n" +
		"    - [\"stub-prep\", \"write\", \"zig-out/lib/libnative.a\", \"ok\"]\n" +
		"    - [\"stub-prep\", \"check\", \"zig-out/lib/libnative.a\"]\n"
	cases := []struct {
		name, kind, yaml, reqFile, wantNote string
		wantPrefixes                        []string
	}{
		{"cargo", "cargo", fullYAML, "zig-out/lib/libnative.a", "test_prepare ran 2 commands under test_wrapper stub-wrapper --display :99",
			[]string{"--display|:99|stub-prep|write|zig-out/lib/libnative.a|ok", "--display|:99|stub-prep|check|zig-out/lib/libnative.a", "--display|:99|cargo|test|", "--display|:99|cargo|clippy|"}},
		{"go", "go", fullYAML, "zig-out/lib/libnative.a", "test_prepare ran 2 commands under test_wrapper stub-wrapper --display :99",
			[]string{"--display|:99|stub-prep|write|zig-out/lib/libnative.a|ok", "--display|:99|stub-prep|check|zig-out/lib/libnative.a", "--display|:99|go|test|-race|"}},
		{"wrapper-only", "cargo", "version: 1\ngate:\n  test_wrapper: [\"stub-wrapper\", \"--display\", \":99\"]\n", "", "ran under test_wrapper stub-wrapper --display :99",
			[]string{"--display|:99|cargo|test|", "--display|:99|cargo|clippy|"}},
	}
	for i := 0; i < len(cases) && i < 8; i++ {
		tc := cases[i]
		t.Run(tc.name, func(t *testing.T) {
			logs := installPrepShims(t)
			t.Setenv("REQUIRE_WORKTREE_FILE", tc.reqFile)
			t.Setenv("REQUIRE_WRAPPED", "1")
			cfg := newCargoPrepareConfig(t, tc.yaml)
			if tc.kind == "go" {
				cfg = newGoPrepareConfig(t, tc.yaml)
			}
			res, err := runBoundedTestStage(t, cfg)
			if err != nil || res.Status != StagePassed {
				t.Fatalf("wrapped %s stage failed: %+v (%v)", tc.name, res, err)
			}
			assertWrappedWorktreeCalls(t, res.Message, tc.wantNote, readShimLines(t, logs.wrapper), tc.wantPrefixes)
		})
	}
}

// assertWrappedWorktreeCalls checks that stub-wrapper recorded every expected command in the isolated worktree.
func assertWrappedWorktreeCalls(t *testing.T, msg, wantNote string, lines, wantPrefixes []string) {
	t.Helper()
	if !strings.Contains(msg, wantNote) {
		t.Errorf("stage message %q lacks %q", msg, wantNote)
	}
	if len(lines) != len(wantPrefixes) {
		t.Fatalf("wrapper recorded %d calls (%q), want %d", len(lines), lines, len(wantPrefixes))
	}
	for i := 0; i < len(wantPrefixes) && i < 8; i++ {
		dir, args, _ := strings.Cut(lines[i], "\t")
		if !strings.Contains(filepath.ToSlash(dir), "/worktrees/") || !strings.HasPrefix(args, wantPrefixes[i]) {
			t.Errorf("call %d = (%s, %s), want worktree dir and prefix %q", i, dir, args, wantPrefixes[i])
		}
	}
}

// TestTestPrepare_Boundary_UndeclaredKeepsStageOutputByteForByte covers case 5(f):
// omitting gate.test_prepare and gate.test_wrapper preserves today's StageOutput byte-for-byte,
// while declaring test_prepare adds the explicit preparation note to the stage line.
func TestTestPrepare_Boundary_UndeclaredKeepsStageOutputByteForByte(t *testing.T) {
	installPrepShims(t)

	plainCfg := newCargoPrepareConfig(t, "version: 1\n")
	plainCfg.rep.CommitSHA = "0123456789abcdef0123456789abcdef01234567"
	if res, err := runBoundedTestStage(t, plainCfg); err != nil || res.Status != StagePassed {
		t.Fatalf("plain Cargo stage failed: %+v (%v)", res, err)
	}
	const wantPlain = "praetor-gate-output/v2\n" +
		"repository\texample/zig-rust\n" +
		"commit_sha\t0123456789abcdef0123456789abcdef01234567\n" +
		"worktree_clean\ttrue\n" +
		"dry_run\tfalse\n" +
		"stage\tRace-Detector Tests\tpassed\tcargo: " + cargoTestsPassed + "\n"
	if got := string(plainCfg.rep.StageOutput()); got != wantPlain {
		t.Fatalf("undeclared StageOutput changed:\n got %q\nwant %q", got, wantPlain)
	}

	emptyGateCfg := newCargoPrepareConfig(t, "version: 1\ngate: {}\n")
	emptyGateCfg.rep.CommitSHA = plainCfg.rep.CommitSHA
	if _, err := runBoundedTestStage(t, emptyGateCfg); err != nil {
		t.Fatalf("empty gate Cargo stage failed: %v", err)
	}
	if got := string(emptyGateCfg.rep.StageOutput()); got != wantPlain {
		t.Fatalf("empty gate StageOutput changed:\n got %q\nwant %q", got, wantPlain)
	}

	prepCfg := newCargoPrepareConfig(t, "version: 1\ngate:\n  test_prepare:\n    - [\"stub-prep\", \"write\", \"zig-out/stamp\", \"1\"]\n")
	prepCfg.rep.CommitSHA = plainCfg.rep.CommitSHA
	if _, err := runBoundedTestStage(t, prepCfg); err != nil {
		t.Fatalf("prepared Cargo stage failed: %v", err)
	}
	wantPrepared := strings.Replace(wantPlain, cargoTestsPassed+"\n", cargoTestsPassed+"; test_prepare ran 1 command\n", 1)
	if got := string(prepCfg.rep.StageOutput()); got != wantPrepared || !slices.Equal([]byte(strings.Replace(got, "; test_prepare ran 1 command", "", 1)), []byte(wantPlain)) {
		t.Fatalf("prepared StageOutput:\n got %q\nwant %q", got, wantPrepared)
	}
}
