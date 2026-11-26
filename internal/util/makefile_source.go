package util

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxMakefileSourceEntries bounds the directory scan for built-in remake sources.
const maxMakefileSourceEntries = 4096

// MakefileImplicitSourceNear checks whether GNU Make could remake base from a sibling in dir.
// The caller pins the directory and supplies the deadline. MakefileImplicitSourceName covers
// built-in rule chains as well as direct sources. A failed or incomplete listing leaves the
// file unprovable, regardless of the selected target or modification times.
func MakefileImplicitSourceNear(ctx context.Context, dir *os.Root, base string) (err error) {
	if ctx == nil || dir == nil || base == "" {
		return errors.New("context, pinned directory and makefile name required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	top, err := dir.Open(".")
	if err != nil {
		return fmt.Errorf("open directory of %s: %w", base, err)
	}
	defer func() { err = errors.Join(err, top.Close()) }()
	entries, err := top.ReadDir(maxMakefileSourceEntries + 1)
	if err != nil {
		return fmt.Errorf("list directory of %s: %w", base, err)
	}
	if len(entries) > maxMakefileSourceEntries {
		return fmt.Errorf("directory of %s holds more than %d entries", base, maxMakefileSourceEntries)
	}
	return checkMakefileSourceEntries(ctx, dir, entries, base)
}

// checkMakefileSourceEntries uses the directory's case behavior when matching sibling names.
func checkMakefileSourceEntries(ctx context.Context, dir *os.Root, entries []os.DirEntry, base string) error {
	foldCase, err := makefileCaseAliases(dir, entries, base)
	if err != nil {
		return err
	}
	matchBase := base
	if foldCase {
		matchBase = strings.ToUpper(base)
	}
	for i := 0; i < len(entries) && i < maxMakefileSourceEntries; i++ {
		name := entries[i].Name()
		if foldCase {
			name = strings.ToUpper(name)
		}
		if MakefileImplicitSourceName(name, matchBase) {
			return fmt.Errorf("%s sits beside %s, which Make may build it from", base, entries[i].Name())
		}
	}
	return ctx.Err()
}

// makefileCaseAliases checks whether sibling matching needs to fold case for this operand.
func makefileCaseAliases(dir *os.Root, entries []os.DirEntry, base string) (bool, error) {
	alternate := strings.ToUpper(base)
	if alternate == base {
		alternate = strings.ToLower(base)
	}
	if alternate == base {
		return makefileRevisionDirectoryVisible(dir)
	}
	return makefileSameEntry(dir, entries, base, alternate)
}

// makefileSameEntry checks that two different spellings resolve to a single listed entry.
func makefileSameEntry(dir *os.Root, entries []os.DirEntry, base, alternate string) (bool, error) {
	alias, err := dir.Lstat(alternate)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	original, err := dir.Lstat(base)
	if err != nil {
		return false, err
	}
	listed := 0
	for i := 0; i < len(entries) && i < maxMakefileSourceEntries; i++ {
		if name := entries[i].Name(); name == base || name == alternate {
			listed++
		}
	}
	return listed < 2 && os.SameFile(original, alias), nil
}

// makefileRevisionDirectoryVisible checks Make's lookup spellings when base has no case variant.
func makefileRevisionDirectoryVisible(dir *os.Root) (bool, error) {
	for _, name := range makefileRevisionDirectories {
		_, err := dir.Lstat(name)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("look up %s: %w", name, err)
		}
	}
	return false, nil
}
