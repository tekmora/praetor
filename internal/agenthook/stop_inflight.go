// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

const (
	maxInflightUnits = 128
	inflightBudget   = 5 * time.Second
	unitStatusBudget = 2 * time.Second
)

// evaluateStopInflight refuses the first Claude Stop with live user units and no pending Bash task.
func evaluateStopInflight(ctx context.Context, client string, stop Canonical, status func(context.Context, []string) ([]string, error)) Verdict {
	switch {
	case client != "claude":
		return inflightSkip("unsupported client " + client)
	case runtime.GOOS != "linux":
		return inflightSkip("systemd user units require Linux (host " + runtime.GOOS + ")")
	case stop.StopActive:
		return inflightSkip("stop_hook_active is already true")
	case stop.TranscriptPath == "":
		return inflightSkip("missing transcript_path")
	}
	ctx, cancel := context.WithTimeout(ctx, inflightBudget)
	defer cancel()
	work := inflightTranscript{session: stop.ConversationID, calls: make(map[string]int), tasks: make(map[string]bool)}
	if err := visitClaudeMainTranscript(ctx, stop.TranscriptPath, work.visit); err != nil {
		return inflightSkip(err.Error())
	}
	verdict := work.verdict(ctx, status)
	verdict.Notice = appendLaneNotice(verdict.Notice, work.launchNotice)
	return verdict
}

// verdict checks the live state of the known launches when the transcript has no pending waiter.
func (work *inflightTranscript) verdict(ctx context.Context, status func(context.Context, []string) ([]string, error)) Verdict {
	if len(work.units) == 0 || len(work.tasks) > 0 {
		return Verdict{Outcome: Allow}
	}
	if len(work.calls) > 0 {
		return inflightSkip("background Bash call has no task receipt")
	}
	probeCtx, cancelProbe := context.WithTimeout(ctx, unitStatusBudget)
	defer cancelProbe()
	states, err := status(probeCtx, work.units)
	if err = errors.Join(err, probeCtx.Err()); err != nil {
		return inflightSkip("systemctl --user is-active: " + err.Error())
	}
	return unitStatusVerdict(work.units, states)
}

// inflightSkip keeps uncertainty visible even when another stop check refuses the turn.
func inflightSkip(reason string) Verdict {
	return Verdict{Outcome: Allow, Notice: "In-flight unit check skipped: " + reason}
}

// runUnitStatus reads one state per literal unit name with one bounded systemctl invocation.
// is-active also prints answers when all units are inactive (exit 3) or gone (exit 4).
func runUnitStatus(ctx context.Context, units []string) ([]string, error) {
	args := append([]string{"--user", "is-active", "--"}, units...)
	out, err := util.RunCommandBytes(ctx, "", "systemctl", 32*maxInflightUnits, args...)
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || !slices.Contains([]int{3, 4}, exit.ExitCode()) || len(out.Stderr) > 0 {
			return nil, err
		}
	}
	return strings.Fields(string(out.Stdout)), nil
}

// unitStatusVerdict matches status rows in argv order and names at most five live units.
func unitStatusVerdict(units, states []string) Verdict {
	if len(states) != len(units) {
		return inflightSkip("systemctl returned an incomplete unit status list")
	}
	var live []string
	for i, state := range states {
		switch state {
		case "active", "activating", "reloading":
			if len(live) < 5 {
				live = append(live, units[i])
			}
		case "inactive", "deactivating", "failed", "maintenance", "refreshing", "unknown":
		default:
			return inflightSkip(fmt.Sprintf("systemctl returned unrecognized state %q", state))
		}
	}
	if len(live) == 0 {
		return Verdict{Outcome: Allow}
	}
	return Verdict{Outcome: Deny, Reason: "Live user units without a background waiter: " +
		strings.Join(live, ", ") + ". To continue, start one background wait on them, or stop them."}
}
