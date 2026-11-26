// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package util

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

// readDirError returns the error the host itself produces reading dir, so every case below
// asserts against the real platform behaviour rather than a constructed error.
func readDirError(t *testing.T, dir string) error {
	t.Helper()
	_, err := os.ReadDir(dir)
	if err == nil {
		t.Fatalf("reading %s unexpectedly succeeded", dir)
	}
	return err
}

func TestDirectoryAbsent_Positive_MissingUnderExistingDirectory(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		filepath.Join(root, "missing"),
		filepath.Join(root, "missing", "deeper", "leaf"),
	} {
		if !DirectoryAbsent(dir, readDirError(t, dir)) {
			t.Fatalf("a directory that does not exist was not reported absent: %s", dir)
		}
	}
}

func TestDirectoryAbsent_Negative_RegularFileIsNotAbsence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "brain.txt")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	// On Windows both reads fail with an error that satisfies fs.ErrNotExist; on POSIX they
	// fail with ENOTDIR. Either way the path is misconfigured, not absent.
	for _, dir := range []string{file, filepath.Join(file, "logs")} {
		if DirectoryAbsent(dir, readDirError(t, dir)) {
			t.Fatalf("a path naming or running through a regular file was reported absent: %s", dir)
		}
	}
}

func TestDirectoryAbsent_Negative_OtherErrorsAreNotAbsence(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cases := map[string]error{
		"nil error":           nil,
		"unrelated error":     errors.New("permission denied"),
		"wrapped unrelated":   fmt.Errorf("read: %w", fs.ErrPermission),
		"empty directory arg": fs.ErrNotExist,
	}
	for name, err := range cases {
		dir := missing
		if name == "empty directory arg" {
			dir = ""
		}
		if DirectoryAbsent(dir, err) {
			t.Fatalf("%s: reported absent", name)
		}
	}
}

func TestDirectoryAbsent_Boundary_ExistingDirectoryAndWrappedError(t *testing.T) {
	root := t.TempDir()
	// A directory that exists by the time absence is judged is not absent, whatever the
	// earlier read said: the caller must surface its error rather than read nothing.
	if DirectoryAbsent(root, fs.ErrNotExist) {
		t.Fatal("an existing directory was reported absent")
	}
	missing := filepath.Join(root, "missing") + string(filepath.Separator)
	wrapped := fmt.Errorf("read transcripts root: %w", readDirError(t, missing))
	if !DirectoryAbsent(missing, wrapped) {
		t.Fatal("a wrapped not-exist error for a missing directory with a trailing separator was not reported absent")
	}
}

// TestSoleCause checks wrapped and singleton joins as well as the depth limit.
// A distinct close cause anywhere in the chain must prevent abbreviation.
func TestSoleCause(t *testing.T) {
	change := errors.New("changed entry")
	closeErr := errors.New("close failed")
	single := fmt.Errorf("stat: %w", errors.Join(change))
	if !errors.Is(SoleCause(single), change) || SoleCause(nil) != nil {
		t.Fatalf("wrong single-cause classification: %v", single)
	}
	if SoleCause(fmt.Errorf("stat: %w", errors.Join(single, closeErr))) != nil {
		t.Fatal("compound failure classified as an isolated change")
	}
	deep := change
	for range 63 {
		deep = errors.Join(deep)
	}
	if !errors.Is(SoleCause(deep), change) || SoleCause(errors.Join(deep)) != nil {
		t.Fatal("expected a single leaf within 64 inspected errors only")
	}
}

// TestMissingDirectoryWalkHasSharedDeadline spends most of the budget at the
// leaf, then expires it at the parent. The third stat must never start.
func TestMissingDirectoryWalkHasSharedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		missing := fmt.Errorf("open corpus: %w", fs.ErrNotExist)
		last := fmt.Errorf("stat parent: %w", fs.ErrNotExist)
		calls := 0
		absent, err := directoryAbsentContext(t.Context(), "missing/parent/leaf", missing, func(string) (os.FileInfo, error) {
			calls++
			time.Sleep(MaxIODuration/2 + time.Second)
			return nil, last
		})
		if absent || calls != 2 || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ancestor walk: absent=%v calls=%d err=%v", absent, calls, err)
		}
		if !errors.Is(err, missing) || !errors.Is(err, last) || t.Context().Err() != nil {
			t.Fatalf("ancestor walk lost a cause or canceled its parent: %v", err)
		}
	})
}
