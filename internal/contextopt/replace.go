package contextopt

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ReplaceOptions binds a write to observed contents or explicit absence. Mode is
// a permission ceiling except for the public bundle files installed by ReplaceScaffoldIn.
type ReplaceOptions struct {
	Expected []byte
	Exists   bool
	Mode     os.FileMode
	// ExpectedLimit raises only the prior snapshot read bound for a bounded recovery.
	ExpectedLimit int64
}

// snapshotPolicy distinguishes strict snapshot writes from idempotent scaffold publication.
type snapshotPolicy int

const (
	strictSnapshot snapshotPolicy = iota
	observedSnapshot
	scaffoldCeiling
	scaffoldExact
)

// ReplaceSnapshot publishes bounded UTF-8 text through a pinned parent directory.
// Cooperative writers serialize on that directory (LockDirectory: the writers of one process
// take turns, and another process's writer is waited for within DirectoryLockBudget);
// replacement checks the prior
// snapshot again before rename. External writers can still race the final check.
// Creation uses an exclusive hard link and never replaces an existing name.
// Any failure once the staging entry exists retains the staged bytes under the
// private .pending name the error reports, so the partial write can be found and
// recovered; only a decided publish drops them.
func ReplaceSnapshot(ctx context.Context, path string, data []byte, options ReplaceOptions) (err error) {
	if err := validateReplacement(ctx, data, options, strictSnapshot); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := validatePath(abs); err != nil {
		return err
	}
	root, err := OpenDirectory(ctx, filepath.Dir(abs))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return replaceInRoot(ctx, root, filepath.Base(abs), data, options, strictSnapshot)
}

// ReplaceRootSnapshot is ReplaceSnapshot for a flat name inside an already pinned
// directory. The caller owns how that directory was opened, so a writer that must stay
// confined below a repository root can pin the directory through that root first and
// still publish through the one locked compare-and-swap implementation.
func ReplaceRootSnapshot(ctx context.Context, root *os.Root, name string, data []byte, options ReplaceOptions) error {
	if err := validateSnapshotName(root, name); err != nil {
		return err
	}
	if err := validateReplacement(ctx, data, options, strictSnapshot); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	return replaceInRoot(ctx, root, name, data, options, strictSnapshot)
}

// validateSnapshotName requires a single file in the pinned directory.
func validateSnapshotName(root *os.Root, name string) error {
	if root == nil || !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return errors.New("snapshot replacement requires a pinned directory and a flat filename")
	}
	return validatePath(name)
}

// replaceInRoot is the locked compare-and-swap publish shared by ReplaceSnapshot and
// ReplaceRootSnapshot: it serializes on root, re-checks the prior snapshot, stages the
// replacement and publishes it.
func replaceInRoot(ctx context.Context, root *os.Root, name string, data []byte, options ReplaceOptions, policy snapshotPolicy) (err error) {
	unlock, err := LockDirectory(ctx, root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	request := replacementRequest{ReplaceOptions: options, data: data, policy: policy}
	mode, satisfied, err := request.verify(ctx, root, name)
	if err != nil || satisfied {
		return err
	}
	stage := ".praetor-" + rand.Text() + ".pending"
	file, err := stageSnapshot(ctx, root, stage, data)
	if err != nil {
		return fmt.Errorf("stage snapshot (inspect %s): %w", stagedPath(root, stage), err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := publishSnapshot(ctx, root, name, stage, file, mode, options); err != nil {
		err = errors.Join(err, file.Chmod(0o600))
		return fmt.Errorf("publish snapshot (inspect %s): %w", stagedPath(root, stage), err)
	}
	return SyncDirectory(ctx, root)
}

// stagedPath names the staging entry the way the operator has to look for it. Every
// publisher reports a retained partial write through this one form (HISS-19); an error
// that names the target ledger instead leaves an orphan nothing can identify, because the
// staging name is random and the audit only knows the five ledger names.
func stagedPath(root *os.Root, stage string) string {
	return filepath.Join(root.Name(), stage)
}

// CreateRootSnapshot writes bounded UTF-8 text under name inside an already pinned
// directory, and only when that name is still free. The content is staged under a private
// random name, written and synced there, and published with an exclusive hard link, so no
// reader and no concurrent creator ever observes name holding a half-written file: it is
// either absent or complete. It reports whether this call published it; losing the race to
// another creator is not an error, because the file that won is the file this call would
// have written. An existing name is left byte-for-byte alone.
func CreateRootSnapshot(ctx context.Context, root *os.Root, name string, data []byte, mode os.FileMode) (created bool, err error) {
	if err := validateReplacement(ctx, data, ReplaceOptions{Mode: mode}, strictSnapshot); err != nil {
		return false, err
	}
	if err := validateSnapshotName(root, name); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	stage := ".praetor-" + rand.Text() + ".pending"
	file, err := stageSnapshot(ctx, root, stage, data)
	if err != nil {
		return false, fmt.Errorf("stage snapshot %s (inspect %s): %w", name, stagedPath(root, stage), err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := syncFileMode(ctx, file, mode); err != nil {
		return false, fmt.Errorf("publish snapshot %s (inspect %s): %w", name, stagedPath(root, stage), err)
	}
	created, err = linkStagedSnapshot(root, name, stage)
	if err != nil {
		return false, fmt.Errorf("publish snapshot %s (inspect %s): %w", name, stagedPath(root, stage), err)
	}
	return created, SyncDirectory(ctx, root)
}

// validateReplacement bounds both the new text and the recovery snapshot expectation.
func validateReplacement(ctx context.Context, data []byte, options ReplaceOptions, policy snapshotPolicy) error {
	if ctx == nil {
		return errors.New("snapshot replacement requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateReplacementLimits(data, options); err != nil {
		return err
	}

	if err := policy.validateMode(options.Mode); err != nil {
		return err
	}
	if !options.Exists && len(options.Expected) != 0 {
		return errors.New("absent snapshot cannot have expected content")
	}
	return errors.Join(validateText(data), validateText(options.Expected))
}

// validateMode restricts exact distribution modes to the scaffold publisher.
func (p snapshotPolicy) validateMode(mode os.FileMode) error {
	if p == scaffoldExact {
		if mode != 0o644 && mode != 0o755 {
			return errors.New("scaffold mode must be 0644 or 0755")
		}
		return nil
	}
	if mode == 0 || mode&^0o644 != 0 {
		return errors.New("snapshot mode must be nonzero owner read/write and optional group/other read bits")
	}
	return nil
}

// validateReplacementLimits bounds new bytes independently from the prior recovery snapshot.
func validateReplacementLimits(data []byte, options ReplaceOptions) error {
	if options.ExpectedLimit < 0 || options.ExpectedLimit > MaxTotalBytes {
		return fmt.Errorf("snapshot expectation limit must be 0..%d bytes", MaxTotalBytes)
	}
	if len(data) > MaxSourceBytes || int64(len(options.Expected)) > replacementReadLimit(options) {
		return fmt.Errorf("snapshot replacement exceeds %d bytes", MaxSourceBytes)
	}
	return nil
}

// replacementReadLimit preserves the default bound unless a recovery explicitly raises it.
func replacementReadLimit(options ReplaceOptions) int64 {
	if options.ExpectedLimit == 0 {
		return MaxSourceBytes
	}
	return options.ExpectedLimit
}

// replacementRequest carries the candidate bytes and private publication policy with the
// caller's snapshot. A strict verification needs only ReplaceOptions.
type replacementRequest struct {
	ReplaceOptions
	data   []byte
	policy snapshotPolicy
}

// isScaffold reports whether a concurrent publication can satisfy this request.
func (r replacementRequest) isScaffold() bool {
	return r.policy == scaffoldExact || r.policy == scaffoldCeiling
}

// verify determines the publication mode from one pinned snapshot. It returns satisfied
// when the requested scaffold is already installed or only needed a mode repair.
func (r replacementRequest) verify(ctx context.Context, root *os.Root, name string) (mode os.FileMode, satisfied bool, err error) {
	_, err = root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && !r.Exists {
		return r.Mode, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !r.Exists && !r.isScaffold() {
		return 0, false, fmt.Errorf("snapshot already exists: %s", name)
	}
	limit := replacementReadLimit(r.ReplaceOptions)
	if r.isScaffold() {
		// The winning publication can be larger than the bounded prior snapshot.
		limit = max(limit, int64(len(r.data)))
	}
	var current bytes.Buffer
	_, err = inspectSnapshot(ctx, root, name, &current, limit, func(file *os.File, info os.FileInfo) error {
		var checkErr error
		mode, satisfied, checkErr = r.checkFile(ctx, file, info, current.Bytes())
		return checkErr
	})
	return mode, satisfied, err
}

// checkFile accepts the expected snapshot or, for an idempotent scaffold, its desired result.
func (r replacementRequest) checkFile(ctx context.Context, file *os.File, info os.FileInfo, current []byte) (os.FileMode, bool, error) {
	mode := r.Mode
	if r.Exists && r.policy != scaffoldExact {
		mode &= info.Mode().Perm()
	}
	matches := r.Exists && bytes.Equal(current, r.Expected)
	if r.isScaffold() && bytes.Equal(current, r.data) {
		if scaffoldModeMatches(info.Mode(), mode) {
			return mode, true, nil
		}
		if matches && r.policy == scaffoldExact {
			return mode, true, repairScaffoldMode(ctx, file, info, mode)
		}
	}
	if !matches {
		return 0, false, fmt.Errorf("snapshot changed before replacement: %s", info.Name())
	}
	return mode, false, nil
}

// repairScaffoldMode changes only the verified descriptor and refuses to change another
// name's permissions when the inode has multiple links.
func repairScaffoldMode(ctx context.Context, file *os.File, info os.FileInfo, mode os.FileMode) error {
	if !singleLink(info) {
		return fmt.Errorf("refusing to change mode of shared or unverified inode: %s", info.Name())
	}
	return syncFileMode(ctx, file, mode)
}

// scaffoldModeMatches compares the whole regular-file mode on POSIX. Windows exposes
// the read-only attribute through the owner write bit.
func scaffoldModeMatches(actual, want os.FileMode) bool {
	if runtime.GOOS == "windows" {
		return actual&0o200 == want&0o200
	}
	return actual == want
}

func stageSnapshot(ctx context.Context, root *os.Root, name string, data []byte) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync()); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func publishSnapshot(ctx context.Context, root *os.Root, name, stage string, file *os.File, mode os.FileMode, options ReplaceOptions) error {
	request := replacementRequest{ReplaceOptions: options}
	if _, _, err := request.verify(ctx, root, name); err != nil {
		return err
	}
	if err := syncFileMode(ctx, file, mode); err != nil {
		return err
	}
	if options.Exists {
		return root.Rename(stage, name)
	}
	created, err := linkStagedSnapshot(root, name, stage)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("snapshot already exists: %s", name)
	}
	return nil
}

// syncFileMode sets the open file's mode and persists it before publication or return.
func syncFileMode(ctx context.Context, file *os.File, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	return file.Sync()
}

// linkStagedSnapshot publishes the staged entry under name with an exclusive hard link.
// It is the one create path ReplaceSnapshot and CreateRootSnapshot both take (HISS-19);
// two copies of it drifted apart on exactly the two questions below.
//
// It reports whether this call published name. os.ErrExist is not a failure: another
// creator won the race, and the file that won is the file this call would have written.
// A decided outcome, published or lost, drops the staging entry; a link that failed for
// any other reason leaves it, because the staged bytes are then the only complete copy
// and the caller names them in its error.
func linkStagedSnapshot(root *os.Root, name, stage string) (bool, error) {
	linkErr := root.Link(stage, name)
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		return false, fmt.Errorf("link snapshot %s: %w", name, linkErr)
	}
	return linkErr == nil, root.Remove(stage)
}

// SyncDirectory persists directory entry changes through an already pinned root.
func SyncDirectory(ctx context.Context, root *os.Root) error {
	if ctx == nil || root == nil {
		return errors.New("directory sync requires a context and pinned root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	// Directory fsync is POSIX-only. Windows refuses it on a directory handle with
	// "Zugriff verweigert"/access denied, which failed the commit-msg live-state gate on every
	// Windows commit. Closing is the whole contract there: NTFS metadata durability does not
	// depend on a caller-issued directory flush the way a POSIX filesystem's does.
	if runtime.GOOS == "windows" {
		return dir.Close()
	}
	return errors.Join(dir.Sync(), dir.Close())
}
