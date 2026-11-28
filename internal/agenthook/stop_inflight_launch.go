// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/cordanaLLM/praetor/internal/forge"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

// literalUnitName accepts literal unit operands, including template instances and systemd hex escapes.
var literalUnitName = regexp.MustCompile(`^(?:[A-Za-z0-9:_.@-]|\\x[0-9A-Fa-f]{2})+$`)

// launches visits simple commands using the hook's shell lexer and admission wrapper grammar.
func (w *inflightTranscript) launches(command, call string) error {
	if !strings.Contains(command, "systemd-run") {
		return nil
	}
	fields, err := launchFields(command)
	if err != nil {
		return fmt.Errorf("read systemd-run command: %w", err)
	}
	start := 0
	priorCommand := false
	for i := 0; i <= len(fields); i++ {
		if i < len(fields) && !targetCommandSeparator(fields[i]) {
			continue
		}
		if i > start {
			if err := w.addLaunch(fields[start:i], call, priorCommand); err != nil {
				return err
			}
			priorCommand = true
		}
		start = i + 1
	}
	return nil
}

// launchFields discards here-document data while retaining the original quoted launch operands.
func launchFields(command string) ([]string, error) {
	if strings.Contains(command, "<<") {
		command = strings.ReplaceAll(command, "\r\n", "\n")
		code, ok := hiss.ShellCode(command, admissionMaxLines)
		if !ok {
			return nil, errors.New("cannot read command with here-document")
		}
		lines := strings.Split(command, "\n")
		for i, line := range code {
			if line == "" {
				lines[i] = ""
			}
		}
		command = strings.Join(lines, "\n")
	}
	return forge.ShellFields(command)
}

// addLaunch looks through known command wrappers and keeps the first occurrence of each unit.
func (w *inflightTranscript) addLaunch(words []string, call string, conditional bool) error {
	for i := range words {
		words[i] = unquoteShellWord(words[i])
	}
	i := skipPrelude(words)
	for _, word := range words[:i] {
		if slices.Contains(admissionPrelude, word) {
			conditional = true
		}
	}
	for depth := 0; i < len(words) && depth < admissionMaxWrappers; depth++ {
		name := path.Base(strings.TrimLeft(words[i], "("))
		if name == "systemd-run" {
			return w.addUnit(words[i+1:], call, conditional)
		}
		if next, ok := admitStep(name, words, i); ok && next >= 0 {
			i = next
			continue
		}
		spec, ok := admissionWrappers[name]
		if !ok {
			break
		}
		i = commandAfter(words, i, spec)
	}
	return nil
}

// addUnit excludes scope and system-manager runs and never passes patterns or expansions to systemctl.
func (w *inflightTranscript) addUnit(args []string, call string, conditional bool) error {
	user, unit := userUnitOption(args)
	if !user || unit == "" {
		return nil
	}
	if len(unit) > 255 || !literalUnitName.MatchString(unit) {
		return errors.New("systemd-run unit name is not a bounded literal")
	}
	if !slices.Contains(w.units, unit) {
		if len(w.units) >= maxInflightUnits {
			return fmt.Errorf("launch count exceeds %d user units", maxInflightUnits)
		}
		w.units = append(w.units, unit)
	}
	if conditional {
		return w.awaitLaunch(unit, call)
	}
	w.confirmUnit(unit)
	return nil
}

// confirmUnit marks a literal launch or a matching start receipt as evidence for this name.
func (w *inflightTranscript) confirmUnit(unit string) {
	if w.confirmed == nil {
		w.confirmed = make(map[string]bool)
	}
	w.confirmed[unit] = true
}

// awaitLaunch keeps conditional candidates keyed by the Bash call that could confirm them.
func (w *inflightTranscript) awaitLaunch(unit, call string) error {
	if w.confirmed[unit] {
		return nil
	}
	if call == "" || len(call) > MaxCorrelationIDBytes {
		return fmt.Errorf("unconfirmed systemd-run launch of %s without a usable Bash tool ID", unit)
	}
	if w.launchCalls == nil {
		w.launchCalls = make(map[string][]string)
	}
	units, exists := w.launchCalls[call]
	if !exists && len(w.launchCalls) >= maxInflightBlocks {
		return errors.New("unconfirmed systemd-run call count exceeds limit")
	}
	if !slices.Contains(units, unit) {
		w.launchCalls[call] = append(units, unit)
	}
	return nil
}

// userUnitOption reads only manager options. Arguments after the child command belong to that command.
func userUnitOption(args []string) (bool, string) {
	user, unit := false, ""
	spec := admissionWrappers["systemd-run"]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			break
		}
		switch arg {
		case "--scope":
			return false, ""
		case "--user":
			user = true
		case "--system":
			user = false
		default:
			if value, next, matched, _ := flagValue(args, i, "-u", "--unit", "-u"); matched {
				unit, i = value, next
			} else if slices.Contains(spec.values, arg) {
				i++
			}
		}
	}
	return user, unit
}
