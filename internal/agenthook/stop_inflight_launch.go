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
func (w *inflightTranscript) launches(command string) error {
	if !strings.Contains(command, "systemd-run") {
		return nil
	}
	fields, err := launchFields(command)
	if err != nil {
		return fmt.Errorf("read systemd-run command: %w", err)
	}
	start := 0
	var firstErr error
	for i := 0; i <= len(fields); i++ {
		if i < len(fields) && !targetCommandSeparator(fields[i]) {
			continue
		}
		if err := w.addLaunch(fields[start:i]); err != nil && firstErr == nil {
			firstErr = err
		}
		start = i + 1
	}
	return firstErr
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
func (w *inflightTranscript) addLaunch(words []string) error {
	for i := range words {
		words[i] = unquoteShellWord(words[i])
	}
	i := skipPrelude(words)
	for depth := 0; i < len(words) && depth < admissionMaxWrappers; depth++ {
		name := path.Base(strings.TrimLeft(words[i], "("))
		if name == "systemd-run" {
			return w.addUnit(words[i+1:])
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
func (w *inflightTranscript) addUnit(args []string) error {
	user, unit := userUnitOption(args)
	if !user || unit == "" || slices.Contains(w.units, unit) {
		return nil
	}
	if len(unit) > 255 || !literalUnitName.MatchString(unit) {
		return errors.New("systemd-run unit name is not a bounded literal")
	}
	if len(w.units) >= maxInflightUnits {
		return fmt.Errorf("launch count exceeds %d user units", maxInflightUnits)
	}
	w.units = append(w.units, unit)
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
