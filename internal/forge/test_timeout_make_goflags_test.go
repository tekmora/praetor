// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

// TestAuditTestTimeouts_MakeGOFLAGSGraph checks export detection and inheritance across literal rules.
func TestAuditTestTimeouts_MakeGOFLAGSGraph(t *testing.T) {
	const export = "release: export GOFLAGS := -timeout=0\n"
	const check = "check: ; go test -timeout=30m ./...\n"
	const inherited = "cannot verify inherited GOFLAGS from Make exports"
	for _, tc := range []struct{ name, makefile, want string }{
		{"independent", export + "release: ; @true\n" + check, ""},
		{"independent long timeout", export + "check: ; go test -timeout=45m ./...\n", ":2 sets 45m, above the 30m bound"},
		{"direct tab recipe", export + "release:\n\tgo test ./...\n", ":3 unverifiable test invocation: " + inherited},
		{"transitive order-only", export + "release:: setup\nsetup: | check\n" + check, ":4 unverifiable test invocation: " + inherited},
		{"multi-target repeated rule", "release publish: override export GOFLAGS = -timeout=0\npublish: ; @true\npublish: ./check\n" + check, ":4 unverifiable test invocation: " + inherited},
		{"no reverse inheritance", export + "check: release ; go test -timeout=30m ./...\nrelease: ; @true\n", ""},
		{"private direct", "check: private export GOFLAGS := -timeout=0\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"private prerequisite", "release: export private GOFLAGS := -timeout=0\nrelease: check\n" + check, ""},
		{"phony is not an edge", "release: export GOFLAGS := -timeout=0\n.PHONY: release check\nrelease: ; @true\n" + check, ""},
		{"phony suppresses implicit search", "release.o: export GOFLAGS := -timeout=0\n.PHONY: release.o\nrelease.c: ; go test -timeout=30m ./...\n", ""},
		{"conditional recipe does not prove implicit search is blocked", "release.o: export GOFLAGS := -timeout=0\nifdef EXPLICIT\nrelease.o: ; @true\nendif\nrelease.c: ; go test -timeout=30m ./...\n", ":5 unverifiable test invocation: " + inherited},
		{"unrelated export assignment value", "export LOG_FIELDS := package GOFLAGS\n" + check, ""},
		{"unrelated eval export assignment value", "$(eval export LOG_FIELDS := package GOFLAGS)\n" + check, ""},
		{"unrelated eval named export", "$(eval export LOG_FIELDS)\n" + check, ""},
		{"immediate eval export assignment", "$(eval export GOFLAGS := -timeout=0)\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"immediate braced eval named export", "RESULT := ${eval override export \\\n GOFLAGS}\nGOFLAGS = -timeout=0\n" + check, ":4 unverifiable test invocation: " + inherited},
		{"nested immediate eval export", "RESULT := $(if yes,$(eval export GOFLAGS := -timeout=0))\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"immediate eval target export", "$(eval check: export GOFLAGS := -timeout=0)\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"deferred eval export not referenced", "RESULT = $(eval export GOFLAGS := -timeout=0)\n" + check, ""},
		{"escaped immediate eval export", "RESULT := $$(eval export GOFLAGS := -timeout=0)\n" + check, ""},
		{"global export assignment", "export GOFLAGS := -timeout=0\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"global named export", "export GOFLAGS\nGOFLAGS = -timeout=0\n" + check, ":3 unverifiable test invocation: " + inherited},
		{"global blanket export", ".EXPORT_ALL_VARIABLES:\nGOFLAGS = -timeout=0\n" + check, ":3 unverifiable test invocation: " + inherited},
		{"read-time command has no target environment", export + "RESULT != go test -timeout=30m ./...\n", ""},
		{"unresolved dependency", export + "release: $(DEPS)\n" + check, ":3 unverifiable test invocation: cannot resolve target graph for inherited GOFLAGS: Makefile:2: unsupported prerequisite $(DEPS)"},
		{"bounded fanout", export + strings.Repeat("release ", 300) + ": " + strings.Repeat("check ", 300) + "\n" + check, ":3 unverifiable test invocation: cannot resolve target graph for inherited GOFLAGS: Makefile:2: target graph exceeds the 65536-entry bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTimeoutFile(t, "Makefile", tc.makefile, tc.want)
		})
	}
}

// TestAuditTestTimeouts_MakeImplicitGOFLAGS compares the audit with GNU Make
// in isolated directories using the current toolchain's go env GOFLAGS.
func TestAuditTestTimeouts_MakeImplicitGOFLAGS(t *testing.T) {
	const export = "release.o: export GOFLAGS := -timeout=0\n"
	const check = "release.c:\n\tgo test -timeout=30m ./...\n"
	const inherited = "unverifiable test invocation: cannot verify inherited GOFLAGS from Make exports"
	for _, tc := range []struct {
		name, fixture, audit, flags string
		goals                       []string
	}{
		{"builtin C rule", export + check, ":3 " + inherited, "-timeout=0\n", []string{"release.o"}},
		{"independent explicit recipes", export + "release.o: ; @:\n" + check, "", "\n", []string{"release.o", "release.c"}},
		{"explicit prerequisite still inherits", export + "release.o: release.c ; @:\n" + check, ":4 " + inherited, "-timeout=0\n", []string{"release.o"}},
		{"private builtin parent", "release.o: private export GOFLAGS := -timeout=0\n" + check, "", "\n", []string{"release.o"}},
		{"distinct directories", "left/release.o: export GOFLAGS := -timeout=0\nright/" + check, "", "\n", []string{"left/release.o", "right/release.c"}},
		{"same basename phony goals", "left/check: export GOFLAGS := -timeout=0\n.PHONY: left/check right/check\nright/check: ; go test -timeout=30m ./...\n", "", "\n", []string{"left/check", "right/check"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTimeoutFile(t, "Makefile", tc.fixture, tc.audit)
			assertMakeGOFLAGSReference(t, tc.fixture, tc.flags, tc.goals)
		})
	}
}

// assertMakeGOFLAGSReference verifies that the go env GOFLAGS process launched by the GNU Make recipe prints exactly want for the requested goals.
func assertMakeGOFLAGSReference(t *testing.T, fixture, want string, goals []string) {
	t.Helper()

	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("GNU Make is not available")
	}
	makePath, err = filepath.Abs(makePath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ctx, goCommand := makeGOFLAGSCommandContext(t, ctx, dir)
	if out, err := util.RunCommand(ctx, dir, makePath, "--version"); err != nil || !strings.HasPrefix(out, "GNU Make ") {
		t.Skip("GNU Make is not available")
	}

	// Only the Make oracle copy is rewritten. Relative redirections work in
	// both sh and cmd without interpolating the temporary directory into a recipe.
	oracle := strings.NewReplacer(
		"go test -timeout=30m ./...", goCommand+" env GOFLAGS > goflags.log",
		"; @:\n", "; @echo noop > noop.log\n",
	).Replace(fixture)
	writeMakeGOFLAGSFixture(t, dir, oracle)
	// Keep the built-in C rule, but send its compiler command to a separate log.
	args := append([]string{"-f", "fixture.mk", "-B", "CC=echo > compiler.log"}, goals...)
	if _, err := util.RunCommand(ctx, dir, makePath, args...); err != nil {
		t.Fatalf("GNU Make fixture: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "goflags.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Fatalf("Make recipe's go env GOFLAGS emitted %q; want %q", got, want)
	}
}

// installMakeGOFLAGSTelemetryOff installs the telemetry-off marker before
// toolchain discovery and returns the directory to pass to Make recipes.
func installMakeGOFLAGSTelemetryOff(t *testing.T, dir string) string {
	t.Helper()

	telemetryDir := filepath.Join(dir, "telemetry")
	if err := os.Mkdir(telemetryDir, util.SecureDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(telemetryDir, "mode"), []byte("off\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_TELEMETRY_DIR", telemetryDir)
	return telemetryDir
}

// makeGOFLAGSCommandContext discovers the installed toolchain with the host
// environment, then gives Make only the toolchain's native bin directory on PATH.
func makeGOFLAGSCommandContext(t *testing.T, ctx context.Context, dir string) (context.Context, string) {
	t.Helper()

	telemetryDir := installMakeGOFLAGSTelemetryOff(t, dir)
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goPath, err = filepath.Abs(goPath)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the host environment for discovery: the host's go may be a shim.
	root, err := util.RunCommand(ctx, dir, goPath, "env", "GOROOT")
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	root = strings.TrimRight(root, "\r\n")
	if !filepath.IsAbs(root) {
		t.Fatalf("go env GOROOT returned a non-absolute path: %q", root)
	}
	bin := filepath.Join(root, "bin")
	goCommand := "go"
	if runtime.GOOS == "windows" {
		goCommand = "go.exe"
	}
	if _, err := exec.LookPath(filepath.Join(bin, goCommand)); err != nil {
		t.Fatalf("installed Go executable: %v", err)
	}

	env := []string{"PATH=" + bin, "LC_ALL=C", "GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=", "TEST_TELEMETRY_DIR=" + telemetryDir}
	if runtime.GOOS == "windows" {
		for _, key := range []string{"ComSpec", "SystemRoot"} {
			if value, ok := os.LookupEnv(key); ok {
				env = append(env, key+"="+value)
			}
		}
	}
	childCtx, err := util.WithCommandEnvironment(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	return childCtx, goCommand
}

// writeMakeGOFLAGSFixture installs the oracle Makefile and prerequisite files.
func writeMakeGOFLAGSFixture(t *testing.T, dir, fixture string) {
	t.Helper()
	for _, f := range []struct {
		name, text string
		mode       os.FileMode
	}{
		{"fixture.mk", fixture, 0600},
		{"release.c", "", 0600},
		{"left/release.c", "", 0600},
	} {
		path := filepath.Join(dir, f.name)
		if err := os.MkdirAll(filepath.Dir(path), util.SecureDirPerm); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f.text), f.mode); err != nil {
			t.Fatal(err)
		}
	}
}
