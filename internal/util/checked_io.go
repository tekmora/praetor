// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package util

import (
	"context"
	"errors"
	"os"
	"time"
)

// MaxIODuration bounds one local fixture I/O operation, including its retries.
const MaxIODuration = 30 * time.Second

// CheckedIO checks cancellation on both sides of one synchronous call. The value
// survives a late return so the caller can release an acquired handle. Cleanup
// itself must run even after cancellation. A live call preserves bare sentinels.
func CheckedIO[T any](ctx context.Context, call func() (T, error)) (T, error) {
	if ctx == nil || call == nil {
		var zero T
		return zero, os.ErrInvalid
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > MaxIODuration {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, MaxIODuration)
		defer cancel()
	}
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	default:
	}
	value, err := call()
	select {
	case <-ctx.Done():
		return value, errors.Join(err, ctx.Err())
	default:
		return value, err
	}
}
