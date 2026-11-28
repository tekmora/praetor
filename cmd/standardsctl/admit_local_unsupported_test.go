// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/admission"
	"github.com/cordanaLLM/praetor/internal/sentinel"
)

// TestLocalAdmitUnsupportedPlatform requires a named refusal with and without an
// ancestor marker. An expired wait or failure to find the command cannot pass.
func TestLocalAdmitUnsupportedPlatform(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv(admitExecutorEnv, "")
	t.Setenv(admitBuilderLimitEnv, "1")
	for _, marker := range []string{"", strconv.Itoa(os.Getppid())} {
		t.Setenv(admitLocalLeaseEnv, marker)
		err := runAdmit([]string{"--local", "--max-load=0", "--min-available-gib=0", "--min-swap-free-gib=0", "--wait=1s", "--", "true"})
		if err == nil || !strings.Contains(err.Error(), runtime.GOOS) || !strings.Contains(err.Error(), "local admission") {
			t.Errorf("local admission with marker %q on %s: %v", marker, runtime.GOOS, err)
		}
	}
}

// TestWaitLocalRefusesBeforeReading requires platform refusal to precede the first host poll.
func TestWaitLocalRefusesBeforeReading(t *testing.T) {
	reads := 0
	waiter := admission.Waiter{Read: func() (sentinel.HostStats, error) {
		reads++
		return sentinel.HostStats{}, errors.New("unexpected host poll")
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, release, err := waiter.WaitLocal(ctx, "unsupported", 1)
	if release != nil {
		if releaseErr := release(); releaseErr != nil {
			t.Error(releaseErr)
		}
	}
	if reads != 0 || err == nil || !strings.Contains(err.Error(), runtime.GOOS) {
		t.Fatalf("local wait on %s: %d reads, %v", runtime.GOOS, reads, err)
	}
}

// TestUnsupportedLocalMarkerAllowsRemoteSelection uses an absent inventory to prove that
// a marker cannot select a local step or interfere with remote selection.
func TestUnsupportedLocalMarkerAllowsRemoteSelection(t *testing.T) {
	inventory := filepath.Join(t.TempDir(), "absent.json")
	t.Setenv(admitExecutorsEnv, inventory)
	t.Setenv(admitExecutorEnv, "")
	t.Setenv(admitBuilderLimitEnv, "1")
	t.Setenv(admitLocalLeaseEnv, strconv.Itoa(os.Getppid()))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	err := runAdmit([]string{"--", "true"})
	if err == nil || !strings.Contains(err.Error(), inventory) {
		t.Fatalf("expected inventory lookup, got %v", err)
	}
}
