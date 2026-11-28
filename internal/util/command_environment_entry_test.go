// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package util

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

const testLeaseMarker = "PRAETOR_ADMIT_LOCAL_LEASE_PID"

// markedCommandContext installs the admission marker without mutating the parent.
func markedCommandContext(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	marked, err := WithCommandEnvironmentEntry(ctx, testLeaseMarker, "42")
	if err != nil {
		t.Fatal(err)
	}
	return marked
}

// constructedEnvironment inspects the real command constructor without starting a child.
func constructedEnvironment(t *testing.T, ctx context.Context, dir string) []string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd, err := boundedCommand(ctx, dir, self, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cmd.Env
}

// TestLeaseMarkerAmbientPWD checks both inherited PWD and the child's working directory,
// late ambient changes, marker replacement and the ambient repository-variable filter.
func TestLeaseMarkerAmbientPWD(t *testing.T) {
	t.Setenv(testLeaseMarker, "old")
	t.Setenv("PWD", t.TempDir())
	t.Setenv("GIT_DIR", "/planted-hook-dir")
	marked := markedCommandContext(t, t.Context())
	t.Setenv("PRAETOR_LATE_ENV_FIXTURE", "late")
	for _, dir := range []string{"", t.TempDir()} {
		base := constructedEnvironment(t, t.Context(), dir)
		want := FilterEnvironment(base, func(name string) bool { return name == testLeaseMarker })
		got := constructedEnvironment(t, marked, dir)
		if !slices.Equal(got, append(want, testLeaseMarker+"=42")) {
			t.Errorf("adding the marker changed the inherited command environment for Dir=%q", dir)
		}
		if slices.Contains(got, "GIT_DIR=/planted-hook-dir") {
			t.Error("ambient repository binding reached the marked command")
		}
	}
}

// TestLeaseMarkerFullAmbient keeps a supported ambient environment of at least 256 entries.
func TestLeaseMarkerFullAmbient(t *testing.T) {
	for i := range 256 {
		t.Setenv(fmt.Sprintf("PRAETOR_ADMIT_FIXTURE_%03d", i), "keep")
	}
	ctx := markedCommandContext(t, t.Context())
	env := constructedEnvironment(t, ctx, "")
	if !slices.Contains(env, "PRAETOR_ADMIT_FIXTURE_255=keep") || !slices.Contains(env, testLeaseMarker+"=42") {
		t.Fatal("full ambient environment lost a retained variable or the marker")
	}
}

// TestLeaseMarkerFullExplicit preserves exactly 256 caller-selected entries and isolation.
func TestLeaseMarkerFullExplicit(t *testing.T) {
	t.Setenv("PRAETOR_PARENT_ONLY", "private")
	entries := []string{"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "PWD=/explicit"}
	for i := len(entries); i < 256; i++ {
		entries = append(entries, fmt.Sprintf("PRAETOR_ADMIT_FIXTURE_%03d=keep", i))
	}
	isolated, err := WithCommandEnvironment(t.Context(), entries)
	if err != nil {
		t.Fatal(err)
	}
	marked := markedCommandContext(t, isolated)
	got := constructedEnvironment(t, marked, t.TempDir())
	if !slices.Equal(got, append(entries, testLeaseMarker+"=42")) {
		t.Fatal("full explicit environment changed or inherited ambient variables")
	}
}
