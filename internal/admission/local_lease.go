// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package admission

import (
	"context"
	"errors"
	"fmt"
)

const localExecutor = "local"

// WaitLocal waits for host headroom and a builder slot in the same polling loop.
// On success the caller owns release until its step finishes.
func (w Waiter) WaitLocal(ctx context.Context, label string, limit int) (Verdict, func() error, error) {
	if limit < 1 {
		return Verdict{}, nil, errors.New("admit: local builder limit must be positive")
	}
	var release func() error
	read := func() (Verdict, error) {
		verdict, err := w.readHost()
		if err != nil || !verdict.Admit {
			return verdict, err
		}
		count, drop, err := AdmitExecutorLease(ctx, localExecutor, limit)
		if err != nil {
			return Verdict{}, err
		}
		if drop == nil {
			return Verdict{Reason: fmt.Sprintf("admit: local builders %d of %d busy", count, limit)}, nil
		}
		release = drop
		return verdict, nil
	}
	verdict, err := w.wait(ctx, label, read)
	return verdict, release, err
}
