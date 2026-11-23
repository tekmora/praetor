// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"errors"
	"fmt"
	"os"
)

// IsolatePushSlotForTestProcess points PRAETOR_TEST_PUSH_SLOT_BASE at a private 0700 directory for
// this test binary. Per-test overrides via t.Setenv still apply inside individual tests.
func IsolatePushSlotForTestProcess() (func(), error) {
	dir, err := os.MkdirTemp("", "praetor-push-slot-*")
	if err != nil {
		return nil, fmt.Errorf("push slot: test isolation temp: %w", err)
	}
	if err := preparePushSlotTestBase(dir); err != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			return nil, errors.Join(err, fmt.Errorf("push slot: test isolation remove: %w", rmErr))
		}
		return nil, err
	}
	return func() {
		if err := os.Unsetenv(pushSlotTestBaseEnv); err != nil {
			fmt.Fprintf(os.Stderr, "push slot test isolation: unsetenv: %v\n", err)
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "push slot test isolation: remove: %v\n", err)
		}
	}, nil
}

// preparePushSlotTestBase makes dir a private, validated push-slot base and points the test-base variable at it.
func preparePushSlotTestBase(dir string) error {
	// #nosec G302 -- a directory needs the owner search bit; 0700 grants nothing to group or others.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("push slot: test isolation chmod: %w", err)
	}
	validated, err := validatePushSlotTestBase(dir)
	if err != nil {
		return fmt.Errorf("push slot: test isolation validate: %w", err)
	}
	if err := ensurePrivateValidatedRuntimeDir(validated, os.Getuid()); err != nil {
		return fmt.Errorf("push slot: test isolation: %w", err)
	}
	if err := os.Setenv(pushSlotTestBaseEnv, validated.path()); err != nil {
		return fmt.Errorf("push slot: test isolation env: %w", err)
	}
	return nil
}
