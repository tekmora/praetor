// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package util

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// DirectoryAbsent reports whether err, returned while reading the directory dir, means that
// dir genuinely does not exist -- the case a caller may treat as "nothing to read".
//
// errors.Is(err, fs.ErrNotExist) alone does not answer that on Windows. Reading a directory
// whose path names a regular file, or runs through one ("brain.txt" or "brain.txt\logs"),
// fails there with ERROR_PATH_NOT_FOUND, which Go maps to fs.ErrNotExist. POSIX reports the
// same mistake as ENOTDIR, which it does not map, so a caller that returned early on
// fs.ErrNotExist refused a misconfigured path on Linux and macOS and silently read it as
// empty on Windows. DirectoryAbsent keeps the POSIX answer on every host: it walks up to the
// nearest ancestor that exists and reports absence only when that ancestor is a directory
// other than dir itself.
//
// A walk that exhausts its bound, or meets any error other than fs.ErrNotExist, reports
// false, so the caller surfaces the original error instead of assuming there was nothing.
// If a stat blocks past the deadline, the walk stops when that stat returns.
func DirectoryAbsent(dir string, err error) bool {
	ctx, cancel := context.WithTimeout(context.Background(), MaxIODuration)
	defer cancel()
	absent, inspectErr := DirectoryAbsentContext(ctx, dir, err)
	return inspectErr == nil && absent
}

// DirectoryAbsentContext bounds the entire ancestor walk, including when the
// caller has no deadline. A failed inspection accompanies the original open error.
func DirectoryAbsentContext(ctx context.Context, dir string, err error) (bool, error) {
	return directoryAbsentContext(ctx, dir, err, os.Stat)
}

// directoryAbsentContext takes each observation under the same walk deadline.
func directoryAbsentContext(ctx context.Context, dir string, openErr error, stat func(string) (os.FileInfo, error)) (bool, error) {
	if ctx == nil {
		return false, errors.Join(openErr, os.ErrInvalid)
	}
	if dir == "" || !SoleNotExist(openErr) {
		return false, openErr
	}
	ctx, cancel := context.WithTimeout(ctx, MaxIODuration)
	defer cancel()
	path := filepath.Clean(dir)
	walk, err := walkToExistingAncestor(path, func(current string) (os.FileInfo, error) {
		return CheckedIO(ctx, func() (os.FileInfo, error) { return stat(current) })
	})
	if err != nil {
		return false, errors.Join(openErr, err)
	}
	if walk.existing == path || !walk.info.IsDir() {
		return false, openErr
	}
	return true, nil
}

// SoleNotExist reports one missing-file cause through ordinary wrappers and singleton
// joins. A second cause (for example, closing the parent) must survive verification.
func SoleNotExist(err error) bool {
	return errors.Is(SoleCause(err), fs.ErrNotExist)
}

// SoleCause returns the single leaf through wrappers and singleton joins.
// Multiple causes or a chain exceeding the inspection bound yield nil.
func SoleCause(err error) error {
	const maxWrappers = 64
	for depth := 0; err != nil && depth < maxWrappers; depth++ {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			causes := joined.Unwrap()
			if len(causes) != 1 {
				return nil
			}
			err = causes[0]
			continue
		}
		if single, ok := err.(interface{ Unwrap() error }); ok {
			err = single.Unwrap()
			continue
		}
		return err
	}
	return nil
}
