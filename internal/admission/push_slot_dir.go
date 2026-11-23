// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// systemTempRoot is the host temporary directory root for push-slot fallbacks.
// Push slot resolution never uses os.TempDir() or TMPDIR so callers cannot fork queues.
const systemTempRoot = "/tmp"

// pushSlotTestBaseEnv names the optional push-slot runtime override for test binaries only.
const pushSlotTestBaseEnv = "PRAETOR_TEST_PUSH_SLOT_BASE"

// pushSlotEnvTestBase returns value when inTest is true and value is non-empty.
// Production admit ignores PRAETOR_TEST_PUSH_SLOT_BASE; only a running test binary honors it
// via testing.Testing().
func pushSlotEnvTestBase(inTest bool, value string) string {
	if inTest && value != "" {
		return value
	}
	return ""
}

// pushSlotValidatedBase is an absolute runtime path accepted by validatePushSlotTestBase.
type pushSlotValidatedBase string

func (b pushSlotValidatedBase) path() string {
	return string(b)
}

// validatePushSlotTestBase refuses relative paths, unclean paths, and any dot-dot element before use.
func validatePushSlotTestBase(raw string) (pushSlotValidatedBase, error) {
	if raw == "" {
		return "", fmt.Errorf("push slot: test base: empty")
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("push slot: test base %q: must be absolute", raw)
	}
	for _, elem := range strings.Split(filepath.ToSlash(raw), "/") {
		if elem == ".." {
			return "", fmt.Errorf("push slot: test base %q: must not contain dot-dot path segments", raw)
		}
	}
	clean := filepath.Clean(raw)
	if clean != raw {
		return "", fmt.Errorf("push slot: test base %q: must equal filepath.Clean of itself", raw)
	}
	return pushSlotValidatedBase(clean), nil
}

// ensurePrivateValidatedRuntimeDir creates and checks a push-slot test runtime root from validatePushSlotTestBase.
func ensurePrivateValidatedRuntimeDir(base pushSlotValidatedBase, uid int) error {
	dir := base.path()
	// #nosec G703 -- dir is from validatePushSlotTestBase (absolute, clean, no dot-dot segments).
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- private runtime needs owner search; 0o700 is least privilege
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// #nosec G703 -- same validated path as the Mkdir call above.
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int(stat.Uid) != uid {
		return fmt.Errorf("%q must be a 0700 directory owned by uid %d", dir, uid)
	}
	return nil
}

// pushSlotRuntimeBase returns the per-user runtime directory for the host push slot.
//
// Resolution is fixed per uid and ignores XDG_RUNTIME_DIR and TMPDIR: when /run/user/<uid>
// exists, is a directory, and is owned by the uid, that path is used; otherwise
// /tmp/praetor-admit-<uid> is created with mode 0700. Executor lease directories keep using
// leaseResourceDir (which may follow XDG_RUNTIME_DIR).
func pushSlotRuntimeBase() (string, error) {
	if base := pushSlotEnvTestBase(testing.Testing(), os.Getenv(pushSlotTestBaseEnv)); base != "" {
		validated, err := validatePushSlotTestBase(base)
		if err != nil {
			return "", err
		}
		uid := os.Getuid()
		if err := ensurePrivateValidatedRuntimeDir(validated, uid); err != nil {
			return "", fmt.Errorf("push slot: runtime base: %w", err)
		}
		return validated.path(), nil
	}
	return hostPushSlotRuntimeBase(os.Getuid())
}

// hostPushSlotRuntimeBase is the production per-uid push-slot runtime root (no test override).
func hostPushSlotRuntimeBase(uid int) (string, error) {
	runUser := filepath.Join("/run", "user", strconv.Itoa(uid))
	if err := ensurePrivateRuntimeDir(runUser, uid); err == nil {
		return runUser, nil
	}
	fallback := filepath.Join(systemTempRoot, fmt.Sprintf("praetor-admit-%d", uid))
	if err := ensurePrivateRuntimeDir(fallback, uid); err != nil {
		return "", fmt.Errorf("push slot: runtime base: %w", err)
	}
	return fallback, nil
}

// pushSlotLeaseDir returns <runtime>/praetor-admit-leases/host-push for the push slot queue.
func pushSlotLeaseDir() (string, error) {
	base, err := pushSlotRuntimeBase()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, executorLeasesDir, PushSlotLeaseResource)
	// #nosec G703 -- PushSlotLeaseResource matches validAdmissionLeaseName under the uid runtime base.
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- lease directory needs owner search; 0o700 is least privilege
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("push slot: lease directory: %w", err)
	}
	return dir, nil
}
