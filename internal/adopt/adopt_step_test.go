// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"testing"
)

// adoptOrStep runs a whole adoption with opts when whole is set, and otherwise only step on the
// session adoption prepares for opts (prepareAdoption), returning the report either way. A test
// that replays one step over many prior-text fixtures keeps one whole adoption and runs the rest
// through the step: a whole adoption costs seconds on Windows, and the internal/adopt package ran
// into its 30-minute timeout there (office-w19a-c1-adopt).
func adoptOrStep(t *testing.T, opts AdoptOptions, whole bool, step func(context.Context, *adoptSession) error) (*AdoptReport, error) {
	t.Helper()
	if whole {
		return Adopt(t.Context(), opts)
	}
	report, s, err := prepareAdoption(t.Context(), opts)
	if err != nil {
		return report, err
	}
	return report, step(t.Context(), s)
}

// chainAdoptSteps composes a bounded slice of reconciliation steps into one adoptStep for
// adoptOrStep when a test asserts an interaction across two or more steps without running the
// whole adoption chain.
func chainAdoptSteps(steps ...adoptStep) adoptStep {
	return func(ctx context.Context, s *adoptSession) error {
		for i := 0; i < len(steps) && i < maxAdoptSteps; i++ {
			if err := steps[i](ctx, s); err != nil {
				return err
			}
		}
		return nil
	}
}
