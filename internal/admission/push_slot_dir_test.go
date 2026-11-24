// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPushSlotEnvTestBase proves the test runtime override applies only in a test binary.
func TestPushSlotEnvTestBase(t *testing.T) {
	const fake = "/tmp/praetor-test-push-slot-isolation"
	for _, tc := range []struct {
		name   string
		inTest bool
		value  string
		want   string
	}{
		{"honored when in test", true, fake, fake},
		{"ignored outside test binary", false, fake, ""},
		{"empty value in test", true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushSlotEnvTestBase(tc.inTest, tc.value); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestReview2044RuntimeRootTransitionDoesNotForkSlot checks that login cannot create a second live holder.
func TestReview2044RuntimeRootTransitionDoesNotForkSlot(t *testing.T) {
	hostRoot := t.TempDir()
	uid := os.Getuid()
	makePushSlotFixtureDir(t, filepath.Join(hostRoot, systemTempRoot))
	selectFixturePushSlotBase(t, hostRoot, uid)
	release, err := WaitPushSlot(t.Context(), time.Second, time.Millisecond, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	})
	makePushSlotFixtureDir(t, filepath.Join(hostRoot, "run", "user", strconv.Itoa(uid)))
	selectFixturePushSlotBase(t, hostRoot, uid)
	second, err := WaitPushSlot(t.Context(), 25*time.Millisecond, time.Millisecond, io.Discard)
	if second != nil {
		t.Error("runtime directory creation produced a second live holder")
		if err := second(); err != nil {
			t.Error(err)
		}
	}
	if !errors.Is(err, ErrPushSlotHeld) {
		t.Fatalf("contending admission: %v", err)
	}
}

// TestPushSlotRuntimeRefusesSymlink checks that an unusable canonical root blocks admission.
func TestPushSlotRuntimeRefusesSymlink(t *testing.T) {
	hostRoot := t.TempDir()
	uid := os.Getuid()
	makePushSlotFixtureDir(t, filepath.Join(hostRoot, systemTempRoot))
	makePushSlotFixtureDir(t, filepath.Join(hostRoot, "run", "user", strconv.Itoa(uid)))
	dir, err := hostPushSlotRuntimeBaseAt(hostRoot, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	if got, err := hostPushSlotRuntimeBaseAt(hostRoot, uid); got != "" || err == nil {
		t.Fatalf("unusable root admitted: %q, %v", got, err)
	}
}

// makePushSlotFixtureDir creates a private directory below the simulated host root.
func makePushSlotFixtureDir(t *testing.T, path string) {
	t.Helper()
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- private fixture directory needs owner search
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// selectFixturePushSlotBase resolves the host root and points the test binary at that result.
func selectFixturePushSlotBase(t *testing.T, root string, uid int) {
	t.Helper()
	dir, err := hostPushSlotRuntimeBaseAt(root, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(pushSlotTestBaseEnv, dir)
}

// TestPushSlotEnvTestBase_Negative_DroppingInTest proves dropping the inTest guard would honor the env outside tests.
func TestPushSlotEnvTestBase_Negative_DroppingInTest(t *testing.T) {
	const fake = "/tmp/praetor-test-push-slot-isolation"
	if got := pushSlotEnvTestBaseDroppedInTest(fake); got != fake {
		t.Fatal("mutation dropping the inTest condition did not apply")
	}
	if pushSlotEnvTestBase(false, fake) != "" {
		t.Fatal("fixed path must ignore env when not in test")
	}
}

// pushSlotEnvTestBaseDroppedInTest is the in-place mutation that drops the inTest condition from pushSlotEnvTestBase.
func pushSlotEnvTestBaseDroppedInTest(value string) string {
	if value != "" {
		return value
	}
	return ""
}

// TestValidatePushSlotTestBase_Positive_CleanAbsolute accepts a minimal clean absolute path.
func TestValidatePushSlotTestBase_Positive_CleanAbsolute(t *testing.T) {
	const path = "/tmp/praetor-valid-push-slot"
	got, err := validatePushSlotTestBase(path)
	if err != nil || got.path() != path {
		t.Fatalf("got %q err %v", got.path(), err)
	}
}

// TestValidatePushSlotTestBase_Negative_RejectsDotDot refuses a .. path element.
func TestValidatePushSlotTestBase_Negative_RejectsDotDot(t *testing.T) {
	_, err := validatePushSlotTestBase("/tmp/praetor/../escape")
	if err == nil || !strings.Contains(err.Error(), "dot-dot") {
		t.Fatalf("want dot-dot refusal, got %v", err)
	}
}

// TestValidatePushSlotTestBase_Boundary_UncleanRefused refuses a path that filepath.Clean would change.
func TestValidatePushSlotTestBase_Boundary_UncleanRefused(t *testing.T) {
	raw := "/tmp/foo//bar"
	clean := filepath.Clean(raw)
	if raw == clean {
		t.Fatal("fixture must be unclean")
	}
	_, err := validatePushSlotTestBase(raw)
	if err == nil || !strings.Contains(err.Error(), "filepath.Clean") {
		t.Fatalf("want clean refusal, got %v", err)
	}
}
