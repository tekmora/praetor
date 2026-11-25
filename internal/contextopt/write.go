package contextopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// WriteSnapshot observes and replaces a current generated artifact, creating its
// parents without following symlinks. Use ReplaceSnapshot when the caller must
// bind publication to an earlier reviewed snapshot instead of the current file.
func WriteSnapshot(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := validateReplacement(ctx, data, ReplaceOptions{Mode: mode}, strictSnapshot); err != nil {
		return err
	}
	if err := EnsureDirectory(ctx, filepath.Dir(path), 0o755); err != nil {
		return err
	}
	before, exists, err := ObserveSnapshot(ctx, path)
	if err != nil {
		return err
	}
	return ReplaceSnapshot(ctx, path, data, ReplaceOptions{Expected: before, Exists: exists, Mode: mode})
}

// WriteSnapshotIn is WriteSnapshot for rel below root, with root as the confinement boundary.
// root must exist; its ancestry is resolved once. Every directory component of rel, existing
// or created, is walked without following a symlink (ensureDirectoryIn), and the file is
// observed and replaced through that pinned parent, so a symlinked
// directory or file inside the governed tree is refused rather than written through.
// WriteSnapshot resolves the ancestry that already exists and would follow it.
func WriteSnapshotIn(ctx context.Context, root, rel string, data []byte, mode os.FileMode) error {
	return replaceSnapshotIn(ctx, root, rel, data, ReplaceOptions{Mode: mode}, observedSnapshot)
}

// ReplaceSnapshotIn is ReplaceSnapshot for rel below root, confined as WriteSnapshotIn is: it
// publishes only while the file still holds options.Expected, or is still absent when
// options.Exists is false. A caller that planned the content from an earlier read binds the
// write to that read, so a concurrent edit fails the publish instead of being overwritten.
func ReplaceSnapshotIn(ctx context.Context, root, rel string, data []byte, options ReplaceOptions) error {
	return replaceSnapshotIn(ctx, root, rel, data, options, strictSnapshot)
}

// ReplaceScaffoldIn publishes an adopted bundle file with its exact distribution mode.
// If another adopter has already published the requested bytes and mode, it succeeds.
// A POSIX mode-only repair changes the verified open file to 0644 or 0755 in place.
// It keeps the bytes, inode, owner, ordinary extended attributes and modification time.
// Chmod can update the ACL mask and change time. Reading may update access time.
// A mode-only repair requires a verified single link. Windows compares the read-only bit.
func ReplaceScaffoldIn(ctx context.Context, root, rel string, data []byte, options ReplaceOptions) error {
	return replaceSnapshotIn(ctx, root, rel, data, options, scaffoldExact)
}

// ReplaceScaffoldTextIn creates a text scaffold at the requested mode or refreshes an
// existing one under the ordinary snapshot permission ceiling. A concurrent adopter's
// matching bytes and mode satisfy either operation. Other changes fail the compare-and-swap.
func ReplaceScaffoldTextIn(ctx context.Context, root, rel string, data []byte, options ReplaceOptions) error {
	return replaceSnapshotIn(ctx, root, rel, data, options, scaffoldCeiling)
}

// replaceSnapshotIn pins the parent of rel below root, creating absent directories without
// following a symlink, and publishes under the snapshot lock. observedSnapshot binds the publish to
// the current file instead of options.Expected and options.Exists.
func replaceSnapshotIn(ctx context.Context, root, rel string, data []byte, options ReplaceOptions, policy snapshotPolicy) (err error) {
	if err := validateReplacement(ctx, data, options, policy); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	dir, err := ensureDirectoryIn(ctx, root, filepath.Dir(rel), 0o755)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	name := filepath.Base(rel)
	if err := validateSnapshotName(dir, name); err != nil {
		return err
	}
	if policy == observedSnapshot {
		options.Expected, options.Exists, err = ObserveRootSnapshot(ctx, dir, name)
		if err != nil {
			return err
		}
	}
	return replaceInRoot(ctx, dir, name, data, options, policy)
}
