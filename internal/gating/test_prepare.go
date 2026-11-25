// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package gating

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/util"
)

// MaxTestPrepareOutputBytes bounds how much of a failed test_prepare command's standard output
// a stage message embeds (HISS-02); standard error is bounded by util.RunCommand.
const MaxTestPrepareOutputBytes = 4096

// testStagePolicy holds gate.test_prepare and gate.test_wrapper from .standards.yaml, read once.
type testStagePolicy struct {
	prepare [][]string
	wrapper []string
}

// loadTestStagePolicy reads gate.test_prepare and gate.test_wrapper from the repository manifest
// once per stage configuration, failing closed on an unreadable or malformed manifest.
func (c *stageConfig) loadTestStagePolicy(ctx context.Context) (testStagePolicy, error) {
	if c.testPolicyLoaded {
		return c.testPolicy, nil
	}
	mCtx, cancel := context.WithTimeout(ctx, GitQueryTimeout)
	defer cancel()
	manifest, err := config.LoadRepositoryManifest(mCtx, c.repoDir)
	if err != nil {
		return testStagePolicy{}, fmt.Errorf("load gate test policy: %w", err)
	}
	if manifest != nil && manifest.Gate != nil {
		c.testPolicy = testStagePolicy{
			prepare: manifest.Gate.PrepareCommands(),
			wrapper: manifest.Gate.WrapperCommand(),
		}
	}
	c.testPolicyLoaded = true
	return c.testPolicy, nil
}

// note renders the stage message clause recording that test preparation and/or wrapper execution
// ran, or returns "" when neither key is declared so undeclared runs keep today's exact output.
func (p testStagePolicy) note() string {
	if len(p.prepare) == 0 && len(p.wrapper) == 0 {
		return ""
	}
	noun := "commands"
	if len(p.prepare) == 1 {
		noun = "command"
	}
	if len(p.prepare) > 0 && len(p.wrapper) > 0 {
		return fmt.Sprintf("test_prepare ran %d %s under test_wrapper %s",
			len(p.prepare), noun, strings.Join(p.wrapper, " "))
	}
	if len(p.prepare) > 0 {
		return fmt.Sprintf("test_prepare ran %d %s", len(p.prepare), noun)
	}
	return fmt.Sprintf("ran under test_wrapper %s", strings.Join(p.wrapper, " "))
}

// runWorktreeTestPrepare verifies PATH availability for any declared test_wrapper and runs every
// declared test_prepare command in order in the isolated worktree dir under the stage bound.
func runWorktreeTestPrepare(tCtx context.Context, tc toolchain, policy testStagePolicy, bound time.Duration, dir string) error {
	if len(policy.wrapper) > 0 {
		if err := requireStageCommand(tCtx, tc, bound, dir, "test_wrapper", policy.wrapper); err != nil {
			return err
		}
	}
	for i := 0; i < len(policy.prepare) && i < config.MaxGateTestPrepareCommands; i++ {
		if err := runOneTestPrepare(tCtx, tc, policy.wrapper, policy.prepare[i], bound, dir); err != nil {
			return err
		}
	}
	return nil
}

// requireStageCommand verifies argv[0] is on the toolchain's PATH, failing closed by name
// (never skipping or passing) when absent or when the stage bound cut the lookup.
func requireStageCommand(tCtx context.Context, tc toolchain, bound time.Duration, dir, role string, argv []string) error {
	display := strings.Join(argv, " ")
	err := tc.have(tCtx, dir, argv[0])
	if err == nil {
		return nil
	}
	if !errors.Is(err, errNotOnPath) {
		if cutErr := cutError(tCtx, role+" "+display, bound, "", dir, err.Error()); cutErr != nil {
			return cutErr
		}
	}
	return fmt.Errorf("%s command %q (%s) is not on PATH%s: %w", role, argv[0], display, tc.where, err)
}

// runOneTestPrepare runs one gate.test_prepare command in dir, prefixed by wrapper when set.
func runOneTestPrepare(tCtx context.Context, tc toolchain, wrapper, cmd []string, bound time.Duration, dir string) error {
	if err := requireStageCommand(tCtx, tc, bound, dir, "test_prepare", cmd); err != nil {
		return err
	}
	execArgv := slices.Concat(wrapper, cmd)
	what := strings.Join(execArgv, " ")
	out, err := tc.run(tCtx, dir, execArgv[0], execArgv[1:]...)
	if err == nil {
		return nil
	}
	excerpt := util.TruncateExcerpt(out, MaxTestPrepareOutputBytes)
	if cutErr := cutError(tCtx, "test_prepare "+what, bound, "", dir, fmt.Sprintf("%s [%v]", excerpt, err)); cutErr != nil {
		return cutErr
	}
	return formatTestPrepareFailure(what, dir, excerpt, err)
}

// formatTestPrepareFailure formats a failed test_prepare command with its display argv,
// exit status, worktree directory, and bounded output excerpt.
func formatTestPrepareFailure(what, dir, excerpt string, err error) error {
	status := exitStatusLabel(err)
	if excerpt != "" {
		if strings.Contains(err.Error(), status) {
			return fmt.Errorf("test_prepare %s failed in %s (%w): %s", what, dir, err, excerpt)
		}
		return fmt.Errorf("test_prepare %s failed in %s (%s: %w): %s", what, dir, status, err, excerpt)
	}
	if strings.Contains(err.Error(), status) {
		return fmt.Errorf("test_prepare %s failed in %s: %w", what, dir, err)
	}
	return fmt.Errorf("test_prepare %s failed in %s (%s): %w", what, dir, status, err)
}

// exitStatusLabel returns "exit status N" when err carries a non-negative ExitCode, else err.Error().
func exitStatusLabel(err error) string {
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return fmt.Sprintf("exit status %d", exit.ExitCode())
	}
	return err.Error()
}

// joinTestNotes joins non-empty stage reason clauses with "; ".
func joinTestNotes(notes ...string) string {
	const maxNotes = 8
	parts := make([]string, 0, len(notes))
	for i := 0; i < len(notes) && i < maxNotes; i++ {
		if notes[i] != "" {
			parts = append(parts, notes[i])
		}
	}
	return strings.Join(parts, "; ")
}
