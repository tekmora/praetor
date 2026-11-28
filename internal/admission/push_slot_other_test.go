// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !unix

package admission

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestWaitPushSlot_Other_Refuses proves non-Unix builds refuse the host push slot.
func TestWaitPushSlot_Other_Refuses(t *testing.T) {
	_, err := WaitPushSlot(context.Background(), time.Second, time.Second, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Unix advisory file locks") {
		t.Fatalf("WaitPushSlot() = %v, want Unix refusal", err)
	}
}
