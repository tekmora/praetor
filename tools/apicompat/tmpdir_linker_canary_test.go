// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package apicompat

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/semver"
	"github.com/cordanaLLM/praetor/internal/util"
)

const (
	goListExportTimeout = 2 * time.Minute
	minLinkerCheckGo    = "1.27.4"
	linkerInputFragment = "in #cgo LDFLAGS"
)

// skipUnlessGo1274LinkerCheck skips unless CGO is available with a C compiler and the
// installed Go toolchain is at least Go 1.27.4, where the local -L linker-input check runs.
func skipUnlessGo1274LinkerCheck(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go command absent: %v", err)
	}
	if os.Getenv("CGO_ENABLED") == "0" {
		t.Skip("CGO_ENABLED=0")
	}
	if cc := os.Getenv("CC"); cc != "" {
		if _, err := exec.LookPath(cc); err != nil {
			t.Skipf("CC=%s not on PATH: %v", cc, err)
		}
	} else if _, err := exec.LookPath("gcc"); err != nil {
		if _, err2 := exec.LookPath("clang"); err2 != nil {
			t.Skipf("no C compiler on PATH (gcc: %v, clang: %v)", err, err2)
		}
	}
	installed, ok := parseGoEnvVersion(t)
	if !ok {
		t.Skip("GOVERSION is not a release toolchain version")
	}
	floor, okFloor := semver.Parse(minLinkerCheckGo)
	if !okFloor || semver.Compare(installed, floor) < 0 {
		t.Skipf("installed Go is below %s for the linker-input check", minLinkerCheckGo)
	}
}

// parseGoEnvVersion reads go env GOVERSION and parses its release triple (before experiment suffix).
func parseGoEnvVersion(t *testing.T) (semver.Version, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	raw, err := util.RunCommand(ctx, "", "go", "env", "GOVERSION")
	if err != nil {
		t.Skipf("go env GOVERSION: %v", err)
	}
	release := strings.TrimPrefix(strings.Split(strings.TrimSpace(raw), "-")[0], "go")
	return semver.Parse(release)
}

// withoutTempEnv drops TMPDIR, TMP, TEMP and GOTMPDIR from inherited environment entries.
func withoutTempEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "TMPDIR", "TMP", "TEMP", "GOTMPDIR":
			continue
		default:
			out = append(out, entry)
		}
	}
	return out
}

// systemTempDir returns os.TempDir() from a child process whose temp variables are unset.
func systemTempDir(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), goListExportTimeout)
	defer cancel()
	dir := t.TempDir()
	prog := filepath.Join(dir, "tempdir.go")
	if err := os.WriteFile(prog, []byte("package main\n\nimport (\"fmt\"; \"os\")\n\nfunc main() { fmt.Print(os.TempDir()) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmdCtx, err := util.WithCommandEnvironment(ctx, withoutTempEnv(os.Environ()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := util.RunCommand(cmdCtx, dir, "go", "run", prog)
	if err != nil {
		t.Fatalf("child temp dir probe: %v\n%s", err, out)
	}
	return strings.TrimSpace(out)
}

// writeCgoSystemTempModule writes a one-package module whose cgo LDFLAGS pass -L with linkDir.
func writeCgoSystemTempModule(t *testing.T, dir, linkDir string) string {
	t.Helper()
	modDir := filepath.Join(dir, "mod")
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission, go_file-permissions_rule-mkdir -- the fixture module tree needs owner traversal to write sibling go.mod and cgo files.
	if err := os.MkdirAll(filepath.Join(modDir, "native"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte("module example.com/apicompat-tmpdir-canary\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cgo := fmt.Sprintf("package native\n\n// #cgo LDFLAGS: -L%s\nimport \"C\"\n\nfunc N() int { return 0 }\n", linkDir)
	if err := os.WriteFile(filepath.Join(modDir, "native", "lib.go"), []byte(cgo), 0o600); err != nil {
		t.Fatal(err)
	}
	return modDir
}

// plantLinkerTrapArchive drops an invalid _pkg_.a under linkDir so Go 1.27.4's -L scan fails.
// linkDir is the shared system temp directory, so the trap is removed when the test ends: a
// leftover file would fail every concurrent build on the host whose cgo passes -L with it.
func plantLinkerTrapArchive(t *testing.T, linkDir string) {
	t.Helper()
	buildDir, err := os.MkdirTemp(linkDir, "go-build")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(buildDir); err != nil {
			t.Errorf("remove planted trap %s: %v", buildDir, err)
		}
	})
	if err := os.WriteFile(filepath.Join(buildDir, "_pkg_.a"), []byte("not-an-archive"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// runGoListExport runs go list -export in moduleDir with extra env and returns exit code and output.
func runGoListExport(t *testing.T, moduleDir string, extra []string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), goListExportTimeout)
	defer cancel()
	cmdCtx, err := util.WithCommandEnvironment(ctx, extra)
	if err != nil {
		t.Fatalf("command environment: %v", err)
	}
	res, err := util.RunCommandBytes(cmdCtx, moduleDir, "go", util.MaxCommandOutputBytes, "list", "-export", "./...")
	combined := string(res.Stdout) + string(res.Stderr)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, combined
	case errors.As(err, &exit):
		return exit.ExitCode(), combined
	default:
		t.Fatalf("go list -export: %v\n%s", err, combined)
		return 0, combined
	}
}

// Positive: with TMPDIR under the module tree, go list -export succeeds even when cgo passes
// -L with the system temp directory. Negative: with TMPDIR unset, Go 1.27.4 fails with the
// linker-input message. Boundary: skipped when cgo, a C compiler, or Go 1.27.4 is absent.
func TestGoListExportTmpdirLinkerCanary(t *testing.T) {
	skipUnlessGo1274LinkerCheck(t)
	systemTemp := systemTempDir(t)
	moduleDir := writeCgoSystemTempModule(t, t.TempDir(), systemTemp)
	plantLinkerTrapArchive(t, systemTemp)
	isolated := filepath.Join(t.TempDir(), "gotmp")
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission, go_file-permissions_rule-mkdir -- go list -export needs a dedicated TMPDIR tree under the fixture.
	if err := os.MkdirAll(isolated, 0o700); err != nil {
		t.Fatal(err)
	}
	if status, out := runGoListExport(t, moduleDir, []string{"TMPDIR=" + isolated}); status != 0 {
		t.Fatalf("TMPDIR under worktree: status %d, want 0:\n%s", status, out)
	}
	status, out := runGoListExport(t, moduleDir, withoutTempEnv(os.Environ()))
	if status == 0 {
		t.Fatalf("TMPDIR unset: status 0, want failure with %q:\n%s", linkerInputFragment, out)
	}
	if !strings.Contains(out, linkerInputFragment) {
		t.Fatalf("TMPDIR unset: output lacks %q:\n%s", linkerInputFragment, out)
	}
}
