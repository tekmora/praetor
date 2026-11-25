// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cordanaLLM/praetor/internal/docstrings"
)

const docstringsCommandTimeout = 30 * time.Second

// runDocstrings dispatches subcommands of `standardsctl docstrings`.
func runDocstrings(args []string) error {
	if len(args) < 1 {
		printDocstringsUsage()
		return nil
	}
	sub := args[0]
	subArgs := args[1:]
	switch sub {
	case "-h", "--help", "help":
		printDocstringsUsage()
		return nil
	case "check":
		return runDocstringsCheck(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] unknown docstrings subcommand: %s\n", sub)
		return exitStatusError{code: 2}
	}
}

// printDocstringsUsage prints help text for the docstrings command.
func printDocstringsUsage() {
	fmt.Println("Usage: standardsctl docstrings <subcommand> [arguments]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  check [--path=.] [--base=<ref>] [--head=<ref>] [--pre-push] [--threshold=80]  Check diff-scoped docstring coverage (modes: error, warning, off)")
}

// runDocstringsCheck executes `standardsctl docstrings check`.
func runDocstringsCheck(args []string) error {
	fs := flag.NewFlagSet("docstrings check", flag.ContinueOnError)
	repoPath := fs.String("path", ".", "Repository root directory")
	baseRef := fs.String("base", "", "Base git reference compared against (defaults to origin/<default-branch>)")
	headRef := fs.String("head", "", "Optional head git reference (defaults to working tree against merge base)")
	prePush := fs.Bool("pre-push", false, "Read pushed ref updates from git pre-push stdin")
	threshold := fs.Int("threshold", docstrings.DefaultThreshold, "Minimum docstring coverage percentage (overrides .coderabbit.yaml)")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return exitStatusError{code: 2}
	}
	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] docstrings check accepts no positional arguments, got %q\n", rest)
		return exitStatusError{code: 2}
	}

	var override *int
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "threshold" {
			val := *threshold
			override = &val
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), docstringsCommandTimeout)
	defer cancel()

	if *prePush {
		if *baseRef != "" || *headRef != "" {
			fmt.Fprintln(os.Stderr, "[ERROR] --pre-push cannot be combined with --base or --head")
			return exitStatusError{code: 2}
		}
		return runDocstringsPrePush(ctx, *repoPath, override, os.Stdin)
	}
	return runDocstringsRange(ctx, *repoPath, *baseRef, *headRef, override)
}

// runDocstringsRange executes a single diff-scoped docstring coverage check.
func runDocstringsRange(ctx context.Context, repoPath, baseRef, headRef string, override *int) error {
	passed, err := reportDocstringsRange(ctx, repoPath, baseRef, headRef, override)
	if err != nil {
		return err
	}
	if !passed {
		return exitStatusError{code: 1}
	}
	return nil
}

// reportDocstringsRange returns the coverage verdict after delivering the complete report.
func reportDocstringsRange(ctx context.Context, repoPath, baseRef, headRef string, override *int) (bool, error) {
	rep, err := docstrings.Check(ctx, docstrings.Options{
		RepoDir:           repoPath,
		BaseRef:           baseRef,
		HeadRef:           headRef,
		ThresholdOverride: override,
	})
	if err != nil {
		if _, writeErr := fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err); writeErr != nil {
			return false, fmt.Errorf("report docstrings check error (%w): %w", err, writeErr)
		}
		return false, exitStatusError{code: 2}
	}
	if err := printDocstringsReport(os.Stdout, rep); err != nil {
		return false, fmt.Errorf("write docstrings report: %w", err)
	}
	return rep.Passed, nil
}

// runDocstringsPrePush reads git pre-push updates from r and checks each pushed range.
func runDocstringsPrePush(ctx context.Context, repoPath string, override *int, r io.Reader) error {
	updates, err := docstrings.ParsePrePushStdin(ctx, r)
	if err != nil {
		if _, writeErr := fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err); writeErr != nil {
			return fmt.Errorf("report pre-push input error (%w): %w", err, writeErr)
		}
		return exitStatusError{code: 2}
	}
	if len(updates) == 0 {
		// lefthook hands stdin to one use_stdin job only; an empty input is stated, never a silent pass.
		return writeDocstringsSkip("no pushed ref update on stdin (a delete-only push, or another hook job read the input)")
	}
	return checkDocstringsUpdates(ctx, repoPath, override, updates)
}

// writeDocstringsSkip delivers the reason a pre-push range was skipped.
func writeDocstringsSkip(reason string) error {
	if _, err := fmt.Fprintf(os.Stdout, "Docstring check: skipped, %s\n", reason); err != nil {
		return fmt.Errorf("write docstrings skip diagnostic: %w", err)
	}
	return nil
}

// checkDocstringsUpdates checks each distinct pushed range and reports updates without a base.
func checkDocstringsUpdates(ctx context.Context, repoPath string, override *int, updates []docstrings.PrePushUpdate) error {
	seen := make(map[string]bool, len(updates))
	failed := false
	for i := 0; i < len(updates); i++ {
		u := updates[i]
		base, skipReason := docstrings.ResolvePrePushBase(ctx, repoPath, "origin", u.LocalOID, u.RemoteOID)
		if base == "" {
			if err := writeDocstringsSkip(fmt.Sprintf("no pushed-range base (%s); CI checks pull request range", skipReason)); err != nil {
				return err
			}
			continue
		}
		key := base + ".." + u.LocalOID
		if seen[key] {
			continue
		}
		seen[key] = true
		passed, err := reportDocstringsRange(ctx, repoPath, base, u.LocalOID, override)
		if err != nil {
			return err
		}
		if !passed {
			failed = true
		}
	}
	if failed {
		return exitStatusError{code: 1}
	}
	return nil
}

// printDocstringsReport writes the summary, uncovered functions and exception dispositions.
func printDocstringsReport(w io.Writer, rep *docstrings.Report) error {
	suffix := ""
	if rep.Mode != "" && rep.Mode != "error" {
		suffix = fmt.Sprintf(" (mode: %s)", rep.Mode)
	}
	if _, err := fmt.Fprintf(w, "Docstring coverage: %.2f%% (%d/%d covered, counted: %d, covered: %d, threshold: %d%%)%s\n",
		rep.Coverage, rep.Covered, rep.Counted, rep.Counted, rep.Covered, rep.Threshold, suffix); err != nil {
		return err
	}
	for i := 0; i < len(rep.Uncovered); i++ {
		u := rep.Uncovered[i]
		if _, err := fmt.Fprintf(w, "%s:%d %s\n", u.Path, u.Line, u.Name); err != nil {
			return err
		}
	}
	return printDocstringExceptions(w, rep.Exceptions)
}

// printDocstringExceptions names and counts each visible exception disposition.
func printDocstringExceptions(w io.Writer, entries []docstrings.ExceptionEntry) error {
	if len(entries) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		counts[entry.Status]++
		if _, err := fmt.Fprintf(w, "Docstring exception %s: %s (category %s, expires %s)\n", entry.Status, entry.Path, entry.Category, entry.Expires); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Docstring exceptions: %d excepted, %d expired, %d stale\n", counts["excepted"], counts["expired"], counts["stale"])
	return err
}
