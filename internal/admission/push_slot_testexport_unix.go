// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"os"
	"testing"
)

// PushSlotTestBase points PRAETOR_TEST_PUSH_SLOT_BASE at a fresh 0700 directory for t, so a test that takes the
// push slot never shares a queue with another test or the host. The base is honored only inside a test binary
// (pushSlotEnvTestBase reads testing.Testing()).
func PushSlotTestBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// #nosec G302 -- a directory needs the owner search bit; 0700 grants nothing to group or others.
	// nosemgrep: go_file-permissions_rule-fileperm, go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a directory needs the owner search bit; 0700 grants nothing to group or others
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	validated, err := validatePushSlotTestBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateValidatedRuntimeDir(validated, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	t.Setenv(pushSlotTestBaseEnv, validated.path())
	return validated.path()
}
