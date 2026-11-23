// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !unix

package admission

import (
	"context"
	"fmt"
	"io"
	"time"
)

// WaitPushSlot refuses on non-Unix platforms because the push slot uses flock-held lease files.
func WaitPushSlot(context.Context, time.Duration, time.Duration, io.Writer) (func() error, error) {
	return nil, fmt.Errorf("push slot: host push slot leases require Unix advisory file locks")
}
