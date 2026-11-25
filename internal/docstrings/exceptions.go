// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package docstrings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// ExceptionEntry identifies the disposition of a declared exception for a counted file.
type ExceptionEntry struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Expires  string `json:"expires"`
	Status   string `json:"status"`
}

type exceptionRun struct {
	entries []config.Exception
	today   time.Time
}

// loadExceptionRun reads docstring exceptions through the shared manifest loader.
func loadExceptionRun(ctx context.Context, root, headRef string) (*exceptionRun, error) {
	entries, err := docstringExceptions(ctx, root, headRef)
	if err != nil {
		return nil, fmt.Errorf("load docstrings exceptions: %w", err)
	}
	return &exceptionRun{entries: entries, today: time.Now().UTC()}, nil
}

// docstringExceptions selects the rule's entries from the manifest paired with the source.
func docstringExceptions(ctx context.Context, root, headRef string) ([]config.Exception, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := readExceptionManifest(ctx, root, headRef)
	if err != nil || data == nil {
		return nil, err
	}
	manifest, err := config.ParseManifest(headRef+":"+config.ManifestFileName, data)
	if err != nil {
		return nil, err
	}
	return config.ExceptionsFor(manifest.Exceptions, config.ExceptionRuleDocstrings), nil
}

// readExceptionManifest follows relative links within the selected repository tree in both modes.
func readExceptionManifest(ctx context.Context, root, headRef string) ([]byte, error) {
	if !isWorktreeHead(headRef) {
		return readCommittedManifest(ctx, root, headRef)
	}
	var data []byte
	err := util.InConfinedDirectory(root, ".", func(dir *os.Root) error {
		var err error
		data, err = util.ReadLimitedIn(dir, config.ManifestFileName, contextopt.MaxSourceBytes)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
	return data, err
}

// readCommittedManifest reads the manifest blob through Git's in-tree symlink resolution.
func readCommittedManifest(ctx context.Context, root, headRef string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, gitReadTimeout)
	defer cancel()
	spec := headRef + ":" + config.ManifestFileName
	input, err := util.WithCommandStdin(ctx, []byte(spec+"\n"))
	if err != nil {
		return nil, err
	}
	// A blob reply frames the raw file bytes with "blob\n" and one final newline.
	const limit = contextopt.MaxSourceBytes + len("blob\n\n")
	out, err := util.RunGitBytes(input, root, limit, "cat-file", "--batch=%(objecttype)", "--follow-symlinks")
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", spec, util.CommandDiagnostic(err, out.Stderr))
	}
	header, body, found := bytes.Cut(out.Stdout, []byte("\n"))
	status := string(header)
	if status == spec+" missing" || strings.HasPrefix(status, "dangling ") {
		return nil, nil
	}
	data, terminated := bytes.CutSuffix(body, []byte("\n"))
	if !found || status != "blob" || !terminated {
		return nil, fmt.Errorf("resolve %s within the repository: expected a blob, got %q", spec, status)
	}
	return data, nil
}

// excuses records stale and expired entries and excuses only a live content-matching file.
func (r *exceptionRun) excuses(rel string, data []byte, rep *Report) bool {
	if len(r.entries) == 0 {
		return false
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	var matching []config.Exception
	for i := 0; i < len(r.entries) && i < config.MaxExceptions; i++ {
		entry := r.entries[i]
		if !entry.Matches(rel) {
			continue
		}
		if !strings.HasPrefix(hash, strings.ToLower(entry.Fingerprint)) {
			rep.recordException(entry, "stale")
			continue
		}
		matching = append(matching, entry)
	}
	live, expired := config.ExceptionFor(matching, rel, r.today, nil)
	if expired != nil {
		rep.recordException(*expired, "expired")
	}
	if live == nil {
		return false
	}
	rep.recordException(*live, "excepted")
	return true
}

// recordException appends one visible disposition, preserving the declared category and expiry.
func (r *Report) recordException(entry config.Exception, status string) {
	r.Exceptions = append(r.Exceptions, ExceptionEntry{
		Path: entry.Path, Category: entry.ExpiryCategory(), Expires: entry.Expires, Status: status,
	})
}
