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

	"github.com/cordanaLLM/praetor/internal/util"
)

// InheritedLocalLease accepts the marker only while the named ancestor has a live local
// lease. A sibling copying the marker and a descendant of a finished step both count anew.
func InheritedLocalLease(ctx context.Context, marker string) (bool, error) {
	owner, err := strconv.Atoi(marker)
	if err != nil || owner < 1 || strconv.Itoa(owner) != marker {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, leaseIOTimeout)
	defer cancel()
	live, err := localOwnerHasLease(ctx, marker)
	if err != nil || !live {
		return false, err
	}
	return localAncestor(ctx, owner)
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
func localOwnerHasLease(ctx context.Context, owner string) (live bool, resultErr error) {
	dir, err := executorLeaseDir(localExecutor)
	if err != nil {
		return false, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, fmt.Errorf("admit: open local lease directory: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	names, err := peerExecutorLeaseNames(localExecutor, "", root)
	if err != nil {
		return false, err
	}
	for i := 0; i < len(names) && i < maxExecutorLeaseFiles; i++ {
		if strings.HasPrefix(names[i], owner+"-") {
			held, err := probeExecutorLease(ctx, localExecutor, root, names[i])
			if err != nil || held {
				return held, err
			}
		}
	}
	return false, nil
}
