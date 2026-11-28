package adopt

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// makefileExpander returns a Makefile's text with the includes the ownership check may follow
// replaced by the fragments they name (util.MakefileExpandIncludes), and a note for each include
// it did not follow that names the path and the cause. Its text is read, never written.
type makefileExpander func(string) (string, []string)

// includeExpander follows the literal includes of the repository's Makefile that name a regular,
// tracked, symlink-free text file inside the repository (readTrackedFragment). Anything else stays
// an include line, which the reader treats as ambiguous (#843); the cause of each refusal comes
// back as a note.
func (s *adoptSession) includeExpander(ctx context.Context) makefileExpander {
	return func(data string) (string, []string) {
		var notes []string
		expanded, remade := util.MakefileExpandIncludesReport(data, func(operand string) (string, bool) {
			text, err := readTrackedFragment(ctx, s.repoPath, operand)
			if err != nil {
				notes = append(notes, fmt.Sprintf("include %s not followed: %v", operand, err))
			}
			return text, err == nil
		})
		return expanded, append(notes, remade...)
	}
}

// makefileImplicitSourceNear checks the included file's pinned parent for built-in remake sources.
func makefileImplicitSourceNear(ctx context.Context, root, rel string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	dir, base := path.Split(rel)
	handle, err := contextopt.OpenDirectoryIn(ctx, root, path.Join(".", dir))
	if err != nil {
		return fmt.Errorf("read directory of %s: %w", rel, err)
	}
	defer func() { err = errors.Join(err, handle.Close()) }()
	return util.MakefileImplicitSourceNear(ctx, handle, base)
}

// readTrackedFragment returns the text of the file rel names below root when git tracks it under
// exactly that spelling and contextopt reads it as a bounded, regular, UTF-8 text file with no
// symlink on the way (ObserveSnapshotIn). An untracked, generated, missing, escaping or oversized
// file, a git or context failure, or a file Make may remake returns an error naming the cause.
func readTrackedFragment(ctx context.Context, root, rel string) (string, error) {
	clean := path.Clean(rel)
	if !filepath.IsLocal(filepath.FromSlash(clean)) {
		return "", errors.New("path leaves the repository")
	}
	untracked, err := util.GitUntrackedPaths(ctx, root, []string{clean})
	if err != nil {
		return "", fmt.Errorf("git tracking check failed: %w", err)
	}
	if len(untracked) != 0 {
		return "", errors.New("file is not tracked by git")
	}
	if err := makefileImplicitSourceNear(ctx, root, clean); err != nil {
		return "", err
	}
	data, exists, err := contextopt.ObserveSnapshotIn(ctx, root, filepath.FromSlash(clean))
	if err != nil {
		return "", fmt.Errorf("file is not a readable regular text file: %w", err)
	}
	if !exists {
		return "", errors.New("file does not exist")
	}
	return string(data), nil
}
