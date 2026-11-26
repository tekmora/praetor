// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// installedTemplateDigest matches one canonical SHA-256 line in the private adoption ledger.
var installedTemplateDigest = regexp.MustCompile("^[0-9a-f]{64}\n$")

// scaffoldInstalledTemplate pins the repository for the whole operation. A live install
// holds its directory lock from template name selection through digest publication.
// Template and record publishers take their own locks on strict descendants.
func (s *adoptSession) scaffoldInstalledTemplate(ctx context.Context) (err error) {
	budget := contextopt.DirectoryLockBudget
	lockCtx, cancel := context.WithTimeoutCause(ctx, budget, fmt.Errorf("%s wait budget: %w", budget, context.DeadlineExceeded))
	defer cancel()
	root, err := contextopt.OpenDirectory(lockCtx, s.repoPath)
	if err != nil {
		return fmt.Errorf("open repository for PR template adoption lock: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if s.opts.DryRun {
		return s.installPullRequestTemplate(ctx, root)
	}
	unlock, err := contextopt.LockDirectory(lockCtx, root)
	if err != nil {
		return fmt.Errorf("acquire PR template adoption lock on %s: %w", root.Name(), err)
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return s.installPullRequestTemplate(ctx, root)
}

// installedTemplatePath prefers the uppercase spelling when present, refusing a linked
// directory or filename before scaffolding. Missing directories are left for the writer.
func installedTemplatePath(ctx context.Context, root *os.Root) (_ string, _ bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	parent := filepath.Dir(filepath.FromSlash(prTemplateFile))
	dir, err := contextopt.OpenDirectoryBelow(ctx, root, parent)
	if errors.Is(err, os.ErrNotExist) {
		return prTemplateFile, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("locate PR template in %s: %w", parent, err)
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for _, rel := range [...]string{prTemplateUpper, prTemplateFile} {
		info, err := dir.Lstat(filepath.Base(rel))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", false, fmt.Errorf("locate %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("refusing symlink at %s", rel)
		}
		return rel, true, nil
	}
	return prTemplateFile, false, nil
}

// reconcileInstalledTemplate recognizes the last installation alongside known releases.
// A dry run, failed write or preserved edit leaves the record untouched.
func (s *adoptSession) reconcileInstalledTemplate(ctx context.Context, sc scaffold, templateExists bool) error {
	record := filepath.Join(workingDirPath, "adopt-installed", filepath.FromSlash(sc.rel)+".sha256")
	before, exists, err := contextopt.ObserveSnapshotBelow(ctx, sc.root, record, true)
	if err != nil {
		return fmt.Errorf("read template install record %s: %w", record, err)
	}
	if exists {
		if !installedTemplateDigest.Match(before) {
			return fmt.Errorf("template install record %s must contain one lowercase SHA-256 line", record)
		}
		sc.prior = maps.Clone(sc.prior)
		sc.prior[strings.TrimSuffix(string(before), "\n")] = "last installed template"
	}
	state, err := s.scaffoldAt(ctx, filepath.FromSlash(sc.rel), sc, templateExists)
	if err != nil || s.opts.DryRun {
		return err
	}
	if state == scaffoldWritten || state == scaffoldIdentical {
		return s.confirmInstalledTemplate(ctx, sc, record, before, exists)
	}
	return nil
}

// confirmInstalledTemplate records the installed bytes only while they match the requested
// rendering. A CRLF checkout retains the same canonical digest as the LF rendering.
func (s *adoptSession) confirmInstalledTemplate(ctx context.Context, sc scaffold, record string, before []byte, exists bool) error {
	installed, present, err := contextopt.ObserveSnapshotBelow(ctx, sc.root, filepath.FromSlash(sc.rel), false)
	if err != nil {
		return fmt.Errorf("read installed template %s: %w", sc.rel, err)
	}
	match, err := util.CanonicalTextEquivalent(installed, sc.content)
	if err != nil {
		return fmt.Errorf("compare installed template %s: %w", sc.rel, err)
	}
	if !present || !match {
		return fmt.Errorf("installed template %s changed before recording its digest", sc.rel)
	}
	return s.recordInstalledTemplate(ctx, sc.root, record, before, exists, installed)
}

// recordInstalledTemplate binds the update to the previously observed record. Recording a
// verified match also repairs a missing record after an interrupted installation.
func (s *adoptSession) recordInstalledTemplate(ctx context.Context, root *os.Root, record string, before []byte, exists bool, content []byte) error {
	digest, _, err := util.CanonicalTextDigest(content)
	if err != nil {
		return fmt.Errorf("digest installed template for %s: %w", record, err)
	}
	line := digest + "\n"
	if string(before) == line {
		return nil
	}
	if err := ensurePrivateWorkingDirBelow(ctx, root); err != nil {
		return err
	}
	if err := contextopt.ReplaceSnapshotBelow(ctx, root, record, []byte(line), contextopt.ReplaceOptions{
		Expected: before, Exists: exists, Mode: 0o600, AcceptCurrent: true,
	}); err != nil {
		writeErr := fmt.Errorf("write template install record %s: %w", record, err)
		if errors.Is(err, contextopt.ErrNonDirectoryComponent) {
			s.report.addError("%s", writeErr)
			return nil
		}
		return writeErr
	}
	return nil
}
