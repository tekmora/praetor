// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package admission

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

const (
	pushSlotLockLabel  = "host push slot"
	pushSlotHolderName = "holder.lock"
)

// WaitPushSlot joins the host push-slot queue, waits until this caller is the oldest live lease
// holder and holds the exclusive slot lock, or maxWait elapses. The returned release closure must
// run when the step ends for any reason.
func WaitPushSlot(ctx context.Context, maxWait, poll time.Duration, log io.Writer) (release func() error, resultErr error) {
	dir, err := pushSlotLeaseDir()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("push slot: lease directory: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, root.Close())
	}()
	ownName, releaseLease, err := createPushSlotLease(dir, root)
	if err != nil {
		return nil, err
	}
	releaseHolder, err := waitForPushSlotGrant(ctx, ownName, root, maxWait, poll, log)
	if err != nil {
		return nil, errors.Join(err, releaseLease())
	}
	return func() error {
		return errors.Join(releaseHolder(), releaseLease())
	}, nil
}

// createPushSlotLease creates and locks this waiter's lease, named by its request time, pid and a random token.
func createPushSlotLease(dir string, root *os.Root) (string, func() error, error) {
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", nil, fmt.Errorf("push slot: lease token: %w", err)
	}
	ownName := fmt.Sprintf("%020d-%d-%s.lock", time.Now().UnixNano(), os.Getpid(), hex.EncodeToString(token[:]))
	return createLockedLease("push slot", dir, root, ownName, pushSlotLockLabel)
}

// waitForPushSlotGrant polls until this lease is oldest, acquires the slot holder lock, or maxWait ends.
func waitForPushSlotGrant(ctx context.Context, ownName string, root *os.Root, maxWait, poll time.Duration, log io.Writer) (func() error, error) {
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	deadline, err := pushSlotWaitDeadline(waitCtx)
	if err != nil {
		return nil, err
	}
	for i := 0; i < maxPolls; i++ {
		release, done, err := pushSlotGrantPollOnce(waitCtx, ownName, root, deadline, poll, log)
		if err != nil || release != nil {
			return release, err
		}
		if done {
			break
		}
	}
	return finalPushSlotGrantAttempt(ownName, root, maxWait)
}

// pushSlotWaitDeadline returns the wait context deadline or an error when none is set.
func pushSlotWaitDeadline(waitCtx context.Context) (time.Time, error) {
	deadline, ok := waitCtx.Deadline()
	if !ok {
		return time.Time{}, fmt.Errorf("push slot: wait context has no deadline")
	}
	return deadline, nil
}

// pushSlotGrantPollOnce tries one grant and, on failure, sleeps until the next poll when time remains. It returns
// a release on a grant, an error, or done=true without either when the deadline ends polling; the caller then makes
// the final grant attempt.
func pushSlotGrantPollOnce(waitCtx context.Context, ownName string, root *os.Root, deadline time.Time, poll time.Duration, log io.Writer) (func() error, bool, error) {
	if err := waitCtx.Err(); err != nil {
		return nil, true, fmt.Errorf("push slot: %w", err)
	}
	granted, release, err := tryGrantPushSlot(ownName, root)
	if err != nil {
		return nil, true, err
	}
	if granted {
		return release, true, nil
	}
	head, queueErr := oldestLivePushSlotLease(root, ownName)
	if queueErr != nil {
		if logErr := pushSlotLogQueueProbe(log, queueErr); logErr != nil {
			return nil, true, logErr
		}
		head = ""
	}
	if !pushSlotSleepBeforeRetry(waitCtx, deadline, poll, log, head) {
		return nil, true, nil
	}
	return nil, false, nil
}

// finalPushSlotGrantAttempt grants the slot after polling ends or refuses when still blocked.
func finalPushSlotGrantAttempt(ownName string, root *os.Root, maxWait time.Duration) (func() error, error) {
	granted, release, err := tryGrantPushSlot(ownName, root)
	if err != nil {
		return nil, err
	}
	if granted {
		return release, nil
	}
	return nil, fmt.Errorf("push slot: still held after %s: %w", maxWait, ErrPushSlotHeld)
}

// pushSlotLogQueueProbe writes a queue-probe failure to log when log is non-nil.
func pushSlotLogQueueProbe(log io.Writer, queueErr error) error {
	if log == nil {
		return nil
	}
	if _, err := fmt.Fprintf(log, "%s push slot wait: queue probe: %v\n", time.Now().Format("15:04:05"), queueErr); err != nil {
		return fmt.Errorf("push slot: queue probe log: %w", err)
	}
	return nil
}

// tryGrantPushSlot reports whether ownName is the oldest live lease and takes the holder lock when it is.
func tryGrantPushSlot(ownName string, root *os.Root) (bool, func() error, error) {
	head, err := oldestLivePushSlotLease(root, ownName)
	if err != nil {
		return false, nil, fmt.Errorf("push slot: %w", err)
	}
	if head != ownName {
		return false, nil, nil
	}
	unlock, busy, err := util.LockPrivateFile(root, pushSlotHolderName, os.O_RDWR|os.O_CREATE, pushSlotHolderLabel)
	if err != nil {
		return false, nil, fmt.Errorf("push slot: holder lock: %w", err)
	}
	if busy {
		return false, nil, nil
	}
	return true, unlock, nil
}

const pushSlotHolderLabel = "host push slot holder"

// pushSlotSleepBeforeRetry logs queue position and sleeps until the next poll or the wait deadline.
func pushSlotSleepBeforeRetry(ctx context.Context, deadline time.Time, poll time.Duration, log io.Writer, head string) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if log != nil {
		if _, err := fmt.Fprintf(log, "%s push slot wait: queued after %s\n", time.Now().Format("15:04:05"), head); err != nil {
			return false
		}
	}
	if err := SleepContext(ctx, min(poll, remaining)); err != nil {
		return false
	}
	return time.Until(deadline) > 0
}

// oldestLivePushSlotLease returns the oldest lease whose flock is still held; dead holders are skipped.
func oldestLivePushSlotLease(root *os.Root, ownName string) (string, error) {
	entries, err := readExecutorLeaseEntries(PushSlotLeaseResource, root)
	if err != nil {
		return "", err
	}
	names := sortedPushSlotLeaseNames(entries)
	for i := 0; i < len(names) && i < maxExecutorLeaseFiles; i++ {
		name := names[i]
		if name == ownName {
			return name, nil
		}
		held, err := probeLeaseFile("push slot", root, name, pushSlotLockLabel)
		if err != nil {
			return "", err
		}
		if held {
			return name, nil
		}
	}
	return "", nil
}

// sortedPushSlotLeaseNames lists the lease file names in request-time order (bounded by maxExecutorLeaseDirEntries).
func sortedPushSlotLeaseNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for i := 0; i < len(entries) && i < maxExecutorLeaseDirEntries; i++ {
		entryName := entries[i].Name()
		if strings.HasSuffix(entryName, ".lock") && entryName != pushSlotHolderName {
			names = append(names, entryName)
		}
	}
	sort.Strings(names)
	return names
}
