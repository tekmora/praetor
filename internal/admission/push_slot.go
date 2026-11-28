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
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(fmt.Errorf("push slot: %w", err), releaseHolder(), releaseLease())
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
	deadline := time.Now().Add(maxWait)
	for i := 0; i < maxPolls && time.Until(deadline) > 0; i++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("push slot: %w", err)
		}
		release, err := pushSlotGrantPollOnce(ownName, root, log)
		if err != nil || release != nil {
			return release, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if err := SleepContext(ctx, min(poll, remaining)); err != nil {
			return nil, fmt.Errorf("push slot: %w", err)
		}
	}
	if time.Until(deadline) > 0 {
		return nil, fmt.Errorf("push slot: poll limit reached: %w", ErrPushSlotHeld)
	}
	return finalPushSlotGrantAttempt(ctx, ownName, root, maxWait)
}

// pushSlotGrantPollOnce tries one grant and logs queue position when the slot is held.
func pushSlotGrantPollOnce(ownName string, root *os.Root, log io.Writer) (func() error, error) {
	granted, release, err := tryGrantPushSlot(ownName, root)
	if err != nil || granted {
		return release, err
	}
	if log == nil {
		return nil, nil
	}
	head, queueErr := oldestLivePushSlotLease(root, ownName)
	if queueErr != nil {
		return nil, pushSlotLogQueueProbe(log, queueErr)
	}
	if _, err := fmt.Fprintf(log, "%s push slot wait: queued after %s\n", time.Now().Format("15:04:05"), head); err != nil {
		return nil, fmt.Errorf("push slot: queue log: %w", err)
	}
	return nil, nil
}

// finalPushSlotGrantAttempt checks the slot once at its wait deadline unless the caller stopped waiting.
func finalPushSlotGrantAttempt(ctx context.Context, ownName string, root *os.Root, maxWait time.Duration) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("push slot: %w", err)
	}
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

// oldestLivePushSlotLease returns the oldest lease whose flock is still held; dead holders are skipped.
func oldestLivePushSlotLease(root *os.Root, ownName string) (string, error) {
	entries, err := readLeaseEntries("push slot", root)
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
