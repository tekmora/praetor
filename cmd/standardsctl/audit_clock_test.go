// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/forge"
)

// auditTodayBeforeJobTimeoutFail is the last day the job-timeout gate warns instead of failing.
func auditTodayBeforeJobTimeoutFail() time.Time {
	return forge.JobTimeoutFailFrom.AddDate(0, 0, -1)
}

// pinAuditToday fixes the calendar day audit gates read as Today until the test ends.
func pinAuditToday(t *testing.T, day time.Time) {
	t.Helper()
	previous := auditToday
	auditToday = func() time.Time { return day }
	t.Cleanup(func() { auditToday = previous })
}
