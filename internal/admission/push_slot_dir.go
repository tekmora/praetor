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
	"strings"
	"syscall"
	"testing"
)

// systemTempRoot is the fixed temporary directory for the per-UID push slot.
// Push slot resolution never uses os.TempDir() or TMPDIR so callers cannot fork queues.
const systemTempRoot = "/tmp"

// pushSlotQueueDir is the private lease directory inside the per-UID push-slot base.
const pushSlotQueueDir = "queue"

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
// The host queue always uses /tmp/praetor-push-slot-<uid>, regardless of XDG_RUNTIME_DIR,
// TMPDIR or the existence of /run/user/<uid>.
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
	return hostPushSlotRuntimeBaseAt("/", os.Getuid())
}

// hostPushSlotRuntimeBaseAt resolves host paths below root, which tests redirect to a private fixture.
func hostPushSlotRuntimeBaseAt(root string, uid int) (string, error) {
	dir := filepath.Join(root, systemTempRoot, fmt.Sprintf("praetor-push-slot-%d", uid))
	if err := ensurePrivateRuntimeDir(dir, uid); err != nil {
		return "", fmt.Errorf("push slot: runtime base: %w", err)
	}
	return dir, nil
}

// pushSlotLeaseDir returns the queue in the push slot's own namespace.
func pushSlotLeaseDir() (string, error) {
	base, err := pushSlotRuntimeBase()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, pushSlotQueueDir)
	if err := ensurePrivateRuntimeDir(dir, os.Getuid()); err != nil {
		return "", fmt.Errorf("push slot: lease directory: %w", err)
	}
	return dir, nil
}
