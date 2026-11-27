// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

type timeoutEnvWrite struct {
	value      string
	set, known bool
}

const timeoutEnvPath = `(?:"\$(?:GITHUB_ENV|\{GITHUB_ENV\})"|\$(?:GITHUB_ENV\b|\{GITHUB_ENV\}))`

var (
	timeoutEnvRedirect = regexp.MustCompile(`>>?[ \t]*` + timeoutEnvPath + `(?:$|[ \t\n;&|)])`)
	timeoutEnvTee      = regexp.MustCompile(`\btee[ \t]+(?:-a[ \t]+)?` + timeoutEnvPath + `(?:$|[ \t\n;&|)])`)
	literalEnvEcho     = regexp.MustCompile(`^echo[ \t]+(.+?)[ \t]+>>[ \t]*` + timeoutEnvPath + `$`)
	envRecordName      = regexp.MustCompile(`^` + parameterName + `=`)
	runnerPathRecord   = regexp.MustCompile(`^"` + parameterName + `=\$(?:RUNNER_TEMP|RUNNER_TOOL_CACHE|GITHUB_WORKSPACE|\{(?:RUNNER_TEMP|RUNNER_TOOL_CACHE|GITHUB_WORKSPACE)\})(?:/[A-Za-z0-9_./-]*)?"$`)
	timeoutEnvControl  = regexp.MustCompile(`^(?:if|then|elif|else|fi|for|while|until|do|done|case|esac|select|function|time|coproc|exit|return|exec|eval|source|\.|!)$`)
)

// workflowTimeoutEnvWrite records explicit writes, not effects of opaque actions.
func workflowTimeoutEnvWrite(spec *ghworkflow.Spec, run ghworkflow.RunStep) timeoutEnvWrite {
	if ghworkflow.NeverRuns(run.Step.If) || !strings.Contains(run.Step.Run, "GITHUB_ENV") {
		return timeoutEnvWrite{}
	}
	script := strings.ReplaceAll(run.Step.Run, "\r\n", "\n")
	source, ok := hiss.WorkflowShellCommandSource(script, maxTimeoutWorkflowLines)
	if !ok {
		return timeoutEnvWrite{set: mentionsTimeoutEnvSink([]byte(script))}
	}
	clean := []byte(script)
	for _, comment := range source.Comments {
		blankTimeoutSpan(clean, comment)
	}
	shell := ghworkflow.StepShell(spec, run.Job, run.Step)
	ordinaryShell := shell == "bash" || shell == "sh"
	always := ordinaryShell && (run.Step.If == "" || run.Step.If == "success()") && run.Step.ContinueOnError == ""
	return orderedTimeoutEnvWrites(clean, source.Commands, ordinaryShell, always)
}

func mentionsTimeoutEnvSink(text []byte) bool {
	return timeoutEnvRedirect.Match(text) || timeoutEnvTee.Match(text)
}

func timeoutEnvCommandSpan(command hiss.ShellCodeCommand) [2]int {
	words := command.Words
	start := words[0].Span[0]
	if len(command.Prefix) != 0 {
		start = command.Prefix[0].Span[0]
	}
	return [2]int{start, words[len(words)-1].Span[1]}
}

// Only a flat sequence establishes execution order. Still inspect each command
// in compound scripts, but do not treat any of their writes as definite.
func flatTimeoutEnvCommands(clean []byte, commands []hiss.ShellCodeCommand) bool {
	end := 0
	for _, command := range commands {
		span := timeoutEnvCommandSpan(command)
		if span[0] < end || strings.Trim(string(clean[end:span[0]]), " \t\n;") != "" {
			return false
		}
		for _, word := range command.Prefix {
			if !envRecordName.MatchString(word.Text) {
				return false
			}
		}
		for i, word := range command.Words {
			if timeoutEnvControl.MatchString(word.Text) && i == 0 || strings.ContainsAny(word.Code, "&|(){};") {
				return false
			}
		}
		end = span[1]
	}
	return strings.Trim(string(clean[end:]), " \t\n;") == ""
}

func orderedTimeoutEnvWrites(clean []byte, commands []hiss.ShellCodeCommand, ordinaryShell, always bool) timeoutEnvWrite {
	sort.SliceStable(commands, func(i, j int) bool {
		return timeoutEnvCommandSpan(commands[i])[0] < timeoutEnvCommandSpan(commands[j])[0]
	})
	always = always && flatTimeoutEnvCommands(clean, commands)
	remaining := append([]byte(nil), clean...)
	var result timeoutEnvWrite
	for _, command := range commands {
		span := timeoutEnvCommandSpan(command)
		text := clean[span[0]:span[1]]
		write := timeoutEnvCommandWrite(text, command, ordinaryShell, always)
		if write.set {
			result = write
		}
		blankTimeoutSpan(remaining, span)
	}
	if mentionsTimeoutEnvSink(remaining) {
		return timeoutEnvWrite{set: true}
	}
	return result
}

func timeoutEnvCommandWrite(text []byte, command hiss.ShellCodeCommand, ordinaryShell, always bool) timeoutEnvWrite {
	if !mentionsTimeoutEnvSink(text) {
		return timeoutEnvWrite{}
	}
	start := timeoutEnvCommandSpan(command)[0]
	if ordinaryShell {
		if payload, ok := timeoutEnvLiteralEchoPayload(text, command, start); ok {
			return timeoutEnvEchoRecord(payload, always)
		}
	}
	masked := append([]byte(nil), text...)
	for _, word := range command.Words {
		if timeoutEnvMaskableLiteral(word) {
			blankTimeoutSpan(masked, [2]int{word.Span[0] - start, word.Span[1] - start})
		}
	}
	return timeoutEnvWrite{set: mentionsTimeoutEnvSink(masked)}
}

// timeoutEnvLiteralEchoPayload matches an unprefixed echo whose captured payload is exactly one shell word.
func timeoutEnvLiteralEchoPayload(text []byte, command hiss.ShellCodeCommand, start int) (hiss.ShellCodeWord, bool) {
	if len(command.Prefix) != 0 || len(command.Words) < 2 {
		return hiss.ShellCodeWord{}, false
	}
	match := literalEnvEcho.FindSubmatchIndex(text)
	if match == nil {
		return hiss.ShellCodeWord{}, false
	}
	payload := command.Words[1]
	if payload.Span != [2]int{start + match[2], start + match[3]} {
		return hiss.ShellCodeWord{}, false
	}
	return payload, true
}

// timeoutEnvMaskableLiteral excludes words that may be part of a sink.
func timeoutEnvMaskableLiteral(word hiss.ShellCodeWord) bool {
	if strings.Contains(word.Code, ">") || !literalTestWord.MatchString(word.Text) {
		return false
	}
	return word.Text != "tee" && word.Text != "-a"
}

func timeoutEnvEchoRecord(payload hiss.ShellCodeWord, always bool) timeoutEnvWrite {
	unknown := timeoutEnvWrite{set: true}
	if !envRecordName.MatchString(payload.Value) || strings.ContainsAny(payload.Value, "\\\r\n") || strings.Contains(payload.Text, "${{") {
		return unknown
	}
	literal := literalTestWord.MatchString(payload.Text)
	value, isGOFLAGS := strings.CutPrefix(payload.Value, "GOFLAGS=")
	if !isGOFLAGS && (literal || runnerPathRecord.MatchString(payload.Text)) {
		return timeoutEnvWrite{}
	}
	if isGOFLAGS && literal && always {
		return timeoutEnvWrite{value: value, set: true, known: true}
	}
	return unknown
}

// readOnlyGOFLAGSPrintf admits a literal format (not printf -v) and data-only
// operands. Leave prefixes and all other commands to the existing mutation check.
func (s timeoutSource) readOnlyGOFLAGSPrintf(script string, command hiss.ShellCodeCommand) bool {
	words := command.Words
	if len(command.Prefix) != 0 || len(words) < 2 || words[0].Text != "printf" || strings.HasPrefix(words[1].Value, "-") || !literalTestWord.MatchString(words[1].Text) {
		return false
	}
	for _, word := range words[1:] {
		if !s.isReadOnlyGOFLAGSPrintfWord(word) {
			return false
		}
	}
	end := words[len(words)-1].Span[1]
	tail := strings.TrimLeft(script[end:], " \t")
	return tail == "" || strings.ContainsRune("\n;#", rune(tail[0]))
}

// isReadOnlyGOFLAGSPrintfWord accepts literal data or an exact quoted GOFLAGS expansion.
func (s timeoutSource) isReadOnlyGOFLAGSPrintfWord(word hiss.ShellCodeWord) bool {
	if s.hasMakeReference(word) || strings.Contains(word.Text, "${{") {
		return false
	}
	return literalTestWord.MatchString(word.Text) || word.Text == `"$GOFLAGS"` || word.Text == `"${GOFLAGS}"`
}
