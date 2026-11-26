// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package adopt

import (
	"context"
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

// scaffoldInstalledTemplate recognizes the rendering last installed at this path alongside
// known release texts. A dry run, failed write or preserved edit leaves the record untouched.
func (s *adoptSession) scaffoldInstalledTemplate(ctx context.Context, sc scaffold) error {
	record := filepath.Join(workingDirPath, "adopt-installed", filepath.FromSlash(sc.rel)+".sha256")
	before, exists, err := contextopt.ObserveSnapshotIn(ctx, s.repoPath, record)
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
		return s.recordInstalledTemplate(ctx, record, before, exists, sc.content)
	}
	return nil
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
		return fmt.Errorf("write template install record %s: %w", record, err)
	}
	return nil
}
