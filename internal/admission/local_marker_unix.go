// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// inheritedLocalLease captures the process identity before verifying ancestry and lease ownership.
func inheritedLocalLease(ctx context.Context, owner int) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, leaseIOTimeout)
	defer cancel()
	identity, err := localProcessIdentity(ctx, owner)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ancestor, err := localAncestor(ctx, owner)
	if err != nil || !ancestor {
		return false, err
	}
	return localOwnerHasLease(ctx, owner, identity)
}

// localProcessIdentity pairs a PID with its kernel start tick to distinguish PID reuse.
func localProcessIdentity(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	tick, err := util.ProcStartTick("/proc", pid)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %d", pid, tick), ctx.Err()
}

// localAncestor walks a bounded parent chain without reading other processes' environments.
func localAncestor(ctx context.Context, owner int) (bool, error) {
	pid := os.Getppid()
	for depth := 0; depth < 128 && pid > 0; depth++ {
		if pid == owner {
			return true, nil
		}
		if pid == 1 {
			return false, nil
		}
		parent, err := localParentPID(ctx, pid)
		if err != nil {
			return false, err
		}
		pid = parent
	}
	return false, nil
}

// localParentPID reads only the parent PID column from the system process table.
func localParentPID(ctx context.Context, pid int) (int, error) {
	out, err := util.RunCommandBytes(ctx, "", "/bin/ps", 256, "-p", strconv.Itoa(pid), "-o", "ppid=")
	if err != nil {
		return 0, fmt.Errorf("admit: read parent of %d: %w", pid, err)
	}
	parent, err := strconv.Atoi(strings.TrimSpace(string(out.Stdout)))
	if err != nil {
		return 0, fmt.Errorf("admit: invalid parent of %d: %w", pid, err)
	}
	return parent, nil
}

// localOwnerHasLease checks the existing private lease files for the marker's holder.
func localOwnerHasLease(ctx context.Context, owner int, identity string) (live bool, resultErr error) {
	dir, err := executorLeaseDir(ctx, localExecutor)
	if err != nil {
		return false, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, fmt.Errorf("admit: open local lease directory: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	// A stale-file scan holds an exclusive flock briefly. Exclude every such scan
	// for the duration of the identity and liveness checks.
	unlock, err := contextopt.LockDirectory(ctx, root)
	if err != nil {
		return false, fmt.Errorf("admit: inspect local lease owner: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	return findLocalOwner(ctx, root, strconv.Itoa(owner)+"-", identity)
}

// findLocalOwner matches the ancestor's PID and process start tick to a live lease.
func findLocalOwner(ctx context.Context, root *os.Root, prefix, identity string) (bool, error) {
	names, err := peerExecutorLeaseNames(localExecutor, "", root)
	if err != nil {
		return false, err
	}
	for i := 0; i < len(names) && i < maxExecutorLeaseFiles; i++ {
		if !strings.HasPrefix(names[i], prefix) {
			continue
		}
		matches, err := matchesLocalHolder(ctx, root, names[i], identity)
		if matches || err != nil {
			return matches, err
		}
	}
	return false, nil
}

// matchesLocalHolder checks the lock and the start tick published by its owner.
func matchesLocalHolder(ctx context.Context, root *os.Root, name, identity string) (bool, error) {
	held, err := probeExecutorLease(ctx, localExecutor, root, name)
	if err != nil || !held {
		return false, err
	}
	recorded, err := util.ReadLimitedIn(root, name, 64)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // Released since the flock check.
	}
	if err != nil {
		return false, err
	}
	return string(recorded) == identity, ctx.Err()
}
