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
)

const pushSlotLockLabel = "host push slot"

// WaitPushSlot joins the host push-slot queue, waits until this caller is the oldest live lease
// holder (first come, first served by request time in the lease file name), or maxWait elapses.
// The returned release closure must run when the step ends for any reason.
func WaitPushSlot(ctx context.Context, maxWait, poll time.Duration, log io.Writer) (release func() error, resultErr error) {
	dir, err := leaseResourceDir(PushSlotLeaseResource, "push slot")
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
	ownName, release, err := createPushSlotLease(dir, root)
	if err != nil {
		return nil, err
	}
	if err := waitUntilPushSlotHead(ctx, ownName, root, maxWait, poll, log); err != nil {
		return nil, errors.Join(err, release())
	}
	return release, nil
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

// waitUntilPushSlotHead polls until this lease is the oldest live one or the wait deadline passes (ErrPushSlotHeld).
func waitUntilPushSlotHead(ctx context.Context, ownName string, root *os.Root, maxWait, poll time.Duration, log io.Writer) error {
	deadline := time.Now().Add(maxWait)
	for i := 0; i < maxPolls; i++ {
		head, err := oldestLivePushSlotLease(root)
		if err != nil {
			return fmt.Errorf("push slot: %w", err)
		}
		if head == ownName {
			return nil
		}
		if !time.Now().Add(poll).Before(deadline) {
			return fmt.Errorf("push slot: still held after %s: %w", maxWait, ErrPushSlotHeld)
		}
		if log != nil {
			if _, err := fmt.Fprintf(log, "%s push slot wait: queued after %s\n", time.Now().Format("15:04:05"), head); err != nil {
				return err
			}
		}
		if err := SleepContext(ctx, poll); err != nil {
			return fmt.Errorf("push slot: %w", err)
		}
	}
	return fmt.Errorf("push slot: more than %d readings, refused", maxPolls)
}

// oldestLivePushSlotLease returns the oldest lease whose flock is still held; dead holders are skipped.
func oldestLivePushSlotLease(root *os.Root) (string, error) {
	entries, err := readExecutorLeaseEntries(PushSlotLeaseResource, root)
	if err != nil {
		return "", err
	}
	names := sortedPushSlotLeaseNames(entries)
	for i := 0; i < len(names) && i < maxExecutorLeaseFiles; i++ {
		held, err := probeLeaseFile("push slot", root, names[i], pushSlotLockLabel)
		if err != nil {
			return "", err
		}
		if held {
			return names[i], nil
		}
	}
	return "", nil
}

// sortedPushSlotLeaseNames lists the lease file names in request-time order (bounded by maxExecutorLeaseDirEntries).
func sortedPushSlotLeaseNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for i := 0; i < len(entries) && i < maxExecutorLeaseDirEntries; i++ {
		entryName := entries[i].Name()
		if strings.HasSuffix(entryName, ".lock") {
			names = append(names, entryName)
		}
	}
	sort.Strings(names)
	return names
}
