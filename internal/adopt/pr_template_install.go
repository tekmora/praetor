// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// installedTemplateDigest matches one canonical SHA-256 line in the private adoption ledger.
var installedTemplateDigest = regexp.MustCompile("^[0-9a-f]{64}\n$")

// scaffoldInstalledTemplate holds the repository directory lock used by publishLock from
// record observation through confirmation. The root exists even on a first adoption or with
// an obstructed ledger. Both snapshot writes lock strict descendants of this directory.
func (s *adoptSession) scaffoldInstalledTemplate(ctx context.Context, sc scaffold) (err error) {
	if s.opts.DryRun {
		return s.reconcileInstalledTemplate(ctx, sc)
	}
	lockCtx, cancel := context.WithTimeout(ctx, contextopt.DirectoryLockBudget)
	defer cancel()
	root, err := contextopt.OpenDirectory(lockCtx, s.repoPath)
	if err != nil {
		return fmt.Errorf("open repository for PR template adoption lock: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	unlock, err := contextopt.LockDirectory(lockCtx, root)
	if err != nil {
		return fmt.Errorf("acquire PR template adoption lock on %s: %w", root.Name(), err)
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return s.reconcileInstalledTemplate(ctx, sc)
}

// reconcileInstalledTemplate recognizes the last installation alongside known releases.
// A dry run, failed write or preserved edit leaves the record untouched.
func (s *adoptSession) reconcileInstalledTemplate(ctx context.Context, sc scaffold) error {
	record := filepath.Join(workingDirPath, "adopt-installed", filepath.FromSlash(sc.rel)+".sha256")
	before, exists, err := contextopt.ObserveOptionalSnapshotIn(ctx, s.repoPath, record)
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
	state, err := s.scaffoldFile(ctx, sc)
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
	installed, present, err := contextopt.ObserveSnapshotIn(ctx, s.repoPath, filepath.FromSlash(sc.rel))
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
	return s.recordInstalledTemplate(ctx, record, before, exists, installed)
}

// recordInstalledTemplate binds the update to the previously observed record. Recording a
// verified match also repairs a missing record after an interrupted installation.
func (s *adoptSession) recordInstalledTemplate(ctx context.Context, record string, before []byte, exists bool, content []byte) error {
	digest, _, err := util.CanonicalTextDigest(content)
	if err != nil {
		return fmt.Errorf("digest installed template for %s: %w", record, err)
	}
	line := digest + "\n"
	if string(before) == line {
		return nil
	}
	if err := ensurePrivateWorkingDir(ctx, s.repoPath); err != nil {
		return err
	}
	if err := contextopt.ReplaceSnapshotIn(ctx, s.repoPath, record, []byte(line), contextopt.ReplaceOptions{
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
