// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build !unix

package admission

import (
	"context"
	"fmt"
)

// AdmitExecutorLease refuses on non-Unix platforms because executor leases require Unix advisory file locks.
func AdmitExecutorLease(_ context.Context, name string, _ int) (int, func() error, error) {
	return 0, nil, fmt.Errorf("executor %s: executor leases require Unix advisory file locks", name)
}

// InheritedLocalLease reports no inherited lease on platforms without advisory locks.
func InheritedLocalLease(context.Context, string) (bool, error) {
	return false, nil
}
