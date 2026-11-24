// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/forge"
)

// auditTodayBeforeJobTimeoutFail is the wall clock, held at the last day the job-timeout gate warns
// instead of failing once that day has passed. Other dated audit checks (exception expiry) keep
// reading today until then, so the repository dogfood audit does not judge them on a future day.
func auditTodayBeforeJobTimeoutFail() time.Time {
	lastWarnDay := forge.JobTimeoutFailFrom.AddDate(0, 0, -1)
	if now := time.Now(); now.Before(lastWarnDay) {
		return now
	}
	return lastWarnDay
}

// pinAuditToday fixes the calendar day audit gates read as Today until the test ends.
func pinAuditToday(t *testing.T, day time.Time) {
	t.Helper()
	previous := auditToday
	auditToday = func() time.Time { return day }
	t.Cleanup(func() { auditToday = previous })
}
