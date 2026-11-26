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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// leaseIOTimeout bounds an attempt to inspect the local runtime directory and its locks.
const leaseIOTimeout = 5 * time.Second

// AdmitExecutorLease creates and locks a per-step lease file under the user's runtime directory
// (<dir>/praetor-admit-leases/<executor>/<pid>-<random>.lock) and returns the inclusive count of
// live steps holding a flock lease on that executor across processes, along with a release
// closure that unlocks and removes the lease file when the step ends. A positive limit
// makes the reservation atomic with the cap decision. When full, the result is the
// number of other live builders and a nil release. Zero requests uncapped remote accounting.
func AdmitExecutorLease(ctx context.Context, name string, limit int) (concurrent int, release func() error, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, leaseIOTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	if err := checkExecutorReservation(name, limit); err != nil {
		return 0, nil, err
	}
	dir, err := executorLeaseDir(ctx, name)
	if err != nil {
		return 0, nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, nil, fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, root.Close())
		if resultErr != nil && release != nil {
			resultErr = errors.Join(resultErr, release())
			concurrent, release = 0, nil
		}
	}()
	// Serialize local publication and counting so simultaneous contenders cannot
	// all count one another's tentative leases and turn away from an empty host.
	if limit > 0 {
		unlock, err := contextopt.LockDirectory(ctx, root)
		if err != nil {
			return 0, nil, fmt.Errorf("admit: local builder reservation: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	}
	return reserveExecutorLease(ctx, name, root, limit)
}

// reserveExecutorLease reclaims peers before publishing a capped reservation while the
// directory lock is held. Uncapped remote contenders publish first so peers can count them.
func reserveExecutorLease(ctx context.Context, name string, root *os.Root, limit int) (int, func() error, error) {
	if limit > 0 {
		count, err := countExecutorLeases(ctx, name, "", root)
		if err != nil || count >= limit {
			return count, nil, err
		}
		_, release, err := createExecutorLease(ctx, name, root)
		if err != nil {
			return 0, nil, err
		}
		return count + 1, release, ctx.Err()
	}
	ownName, release, err := createExecutorLease(ctx, name, root)
	if err != nil {
		return 0, nil, err
	}
	peers, err := countExecutorLeases(ctx, name, ownName, root)
	if err != nil {
		return 0, nil, errors.Join(err, release())
	}
	return peers + 1, release, ctx.Err()
}

// executorRuntimeDir selects one UID-owned local root across launch environments.
// Remote executor accounting retains its XDG and temporary-directory policy.
func executorRuntimeDir(ctx context.Context, name string) (string, error) {
	tmp := "/tmp"
	if name == localExecutor {
		if fixture, ok := ctx.Value(localLeaseTempKey{}).(string); ok {
			tmp = fixture
		}
	} else {
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			return xdg, nil
		}
		tmp = os.TempDir()
	}
	uid := os.Getuid()
	base := filepath.Join(tmp, fmt.Sprintf("praetor-admit-%d", uid))
	return base, ensurePrivateRuntimeDir(base, uid)
}

// checkExecutorReservation validates the platform, name and cap before filesystem I/O.
func checkExecutorReservation(name string, limit int) error {
	if name == localExecutor {
		if err := CheckLocalPlatform(); err != nil {
			return err
		}
		return CheckLocalBuilderLimit(limit)
	}
	if !validExecutorName(name) {
		return fmt.Errorf("executor %s: invalid or reserved executor name", name)
	}
	if limit != 0 {
		return CheckLocalBuilderLimit(limit)
	}
	return nil
}

// executorLeaseDir creates the private runtime path for a validated executor name.
func executorLeaseDir(ctx context.Context, name string) (string, error) {
	base, err := executorRuntimeDir(ctx, name)
	if err != nil {
		return "", fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	dir := filepath.Join(base, executorLeasesDir, name)
	// #nosec G703 -- name matches validExecutorName (alphanumeric, no path separators) under the user's runtime directory.
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a lease directory needs the owner search bit; 0o700 is least privilege
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	return dir, nil
}

// ensurePrivateRuntimeDir ensures that the directory exists with 0700 permissions and is owned by the specified UID.
func ensurePrivateRuntimeDir(dir string, uid int) error {
	// nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission -- a private runtime directory needs the owner search bit; 0o700 is least privilege
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int(stat.Uid) != uid {
		return fmt.Errorf("%q must be a 0700 directory owned by uid %d", dir, uid)
	}
	return nil
}

// createExecutorLease generates and locks a unique lease file, returning its name and a release function.
func createExecutorLease(ctx context.Context, name string, root *os.Root) (string, func() error, error) {
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", nil, fmt.Errorf("executor %s: lease token: %w", name, err)
	}
	ownName := fmt.Sprintf("%d-%s.lock", os.Getpid(), hex.EncodeToString(token[:]))
	tmpName := "." + ownName + ".tmp"
	unlock, busy, err := util.LockPrivateFile(root, tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL, "executor "+name+" lease")
	if err != nil {
		return "", nil, fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	if busy {
		return "", nil, fmt.Errorf("executor %s: lease %s already held", name, ownName)
	}
	ownPath := filepath.Join(root.Name(), ownName)
	if err := publishExecutorLease(ctx, name, root, tmpName, ownName); err != nil {
		return "", nil, errors.Join(fmt.Errorf("executor %s: lease directory: %w", name, err), root.Remove(tmpName), unlock())
	}
	var once sync.Once
	var releaseErr error
	release := func() error {
		once.Do(func() {
			removeErr := os.Remove(ownPath)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
			releaseErr = errors.Join(removeErr, unlock())
		})
		return releaseErr
	}
	return ownName, release, nil
}

// publishExecutorLease records the local holder's Linux process start tick under its
// exclusive lock before renaming the file into view. Remote leases need only the flock.
func publishExecutorLease(ctx context.Context, name string, root *os.Root, tmpName, ownName string) error {
	if name == localExecutor {
		identity, err := localProcessIdentity(ctx, os.Getpid())
		if err != nil {
			return err
		}
		if err := root.WriteFile(tmpName, []byte(identity), 0o600); err != nil {
			return err
		}
	}
	return root.Rename(tmpName, ownName)
}

const maxExecutorLeaseDirEntries = 1024

// countExecutorLeases tallies the active advisory file locks currently held for the specified
// executor, refusing admission when lock files exceed maxExecutorLeaseFiles.
func countExecutorLeases(ctx context.Context, name, ownName string, root *os.Root) (int, error) {
	peers, err := peerExecutorLeaseNames(name, ownName, root)
	if err != nil {
		return 0, err
	}
	concurrent := 0
	for i := 0; i < len(peers) && i < maxExecutorLeaseFiles; i++ {
		held, err := probeExecutorLease(ctx, name, root, peers[i])
		if err != nil {
			return 0, err
		}
		if held {
			concurrent++
		}
	}
	return concurrent, nil
}

// peerExecutorLeaseNames lists peer .lock filenames in root and refuses when total .lock files exceed maxExecutorLeaseFiles.
func peerExecutorLeaseNames(name, ownName string, root *os.Root) ([]string, error) {
	entries, err := readExecutorLeaseEntries(name, root)
	if err != nil {
		return nil, err
	}
	peers := make([]string, 0, min(len(entries), maxExecutorLeaseFiles))
	lockFiles := 0
	for i := 0; i < len(entries) && i < maxExecutorLeaseDirEntries; i++ {
		entryName := entries[i].Name()
		if !strings.HasSuffix(entryName, ".lock") {
			continue
		}
		lockFiles++
		if lockFiles > maxExecutorLeaseFiles {
			return nil, fmt.Errorf("executor %s: %w (%d)", name, ErrExecutorLeaseCap, maxExecutorLeaseFiles)
		}
		if entryName != ownName {
			peers = append(peers, entryName)
		}
	}
	return peers, nil
}

// readExecutorLeaseEntries reads up to maxExecutorLeaseDirEntries plus one directory entries from the lease root.
func readExecutorLeaseEntries(name string, root *os.Root) ([]os.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	entries, readErr := f.ReadDir(maxExecutorLeaseDirEntries + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, fmt.Errorf("executor %s: lease directory: %w", name, err)
	}
	if len(entries) > maxExecutorLeaseDirEntries {
		return nil, fmt.Errorf("executor %s: %w (%d)", name, ErrExecutorLeaseCap, maxExecutorLeaseFiles)
	}
	return entries, nil
}

// probeExecutorLease tests whether a lease file is actively locked, removing stale unheld lock files.
func probeExecutorLease(ctx context.Context, name string, root *os.Root, entryName string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("executor %s: lease scan: %w", name, err)
	}
	unlock, busy, err := util.LockPrivateFile(root, entryName, os.O_RDONLY, "executor "+name+" lease")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("executor %s: %w", name, err)
	}
	if busy {
		return true, nil
	}
	removeErr := root.Remove(entryName)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if err := errors.Join(removeErr, unlock()); err != nil {
		return false, fmt.Errorf("executor %s: remove stale lease %s: %w", name, entryName, err)
	}
	return false, nil
}
