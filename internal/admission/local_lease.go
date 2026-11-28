// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package admission

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
)

const localExecutor = "local"

// CheckLocalPlatform refuses a local step before any host reading or nested exemption.
func CheckLocalPlatform() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("admit: local admission requires Linux, unavailable on %s", runtime.GOOS)
	}
	return nil
}

// CheckLocalBuilderLimit validates a requested cap against the bounded lease scan.
func CheckLocalBuilderLimit(limit int) error {
	if limit < 1 || limit > maxExecutorLeaseFiles {
		return fmt.Errorf("local builder limit requires a positive integer at most %d", maxExecutorLeaseFiles)
	}
	return nil
}

// localLeaseTempKey identifies the fixture filesystem root for per-UID local leases.
type localLeaseTempKey struct{}

// WithLocalLeaseTempRoot substitutes the filesystem's /tmp in an isolated fixture.
// Production callers use the fixed host root regardless of launch environment.
func WithLocalLeaseTempRoot(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, localLeaseTempKey{}, dir)
}

// InheritedLocalLease accepts only a live local admission owned by an ancestor.
// A missing or malformed marker returns false with no error.
func InheritedLocalLease(ctx context.Context, marker string) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil // Remote callers can carry a marker from another host.
	}
	owner, ok := localLeaseOwnerPID(marker)
	if !ok {
		return false, nil
	}
	return inheritedLocalLease(ctx, owner)
}

// localLeaseOwnerPID recognizes positive decimal ints with no sign or leading zero.
func localLeaseOwnerPID(marker string) (int, bool) {
	if marker == "" || marker[0] < '1' || marker[0] > '9' {
		return 0, false
	}
	owner, err := strconv.Atoi(marker)
	return owner, err == nil
}

// WaitLocal waits for host headroom and a builder slot in the same polling loop.
// On success the caller owns release until its step finishes.
func (w Waiter) WaitLocal(ctx context.Context, label string, limit int) (Verdict, func() error, error) {
	if err := CheckLocalPlatform(); err != nil {
		return Verdict{}, nil, err
	}
	if err := CheckLocalBuilderLimit(limit); err != nil {
		return Verdict{}, nil, err
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
