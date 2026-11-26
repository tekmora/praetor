// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var backgroundReceiptID = regexp.MustCompile(`^Command running in background with ID: ([A-Za-z0-9_-]+)(?:[.[:space:]]|$)`)

var unitStartReceipt = regexp.MustCompile(`^Running as unit: ([^;[:space:]]+)(?:; invocation ID: [[:xdigit:]]{32})?$`)

// inflightReceipt collects the task identity and output attributable to a single Bash call.
type inflightReceipt struct {
	taskID string
	output []string
}

// readInflightReceipt distinguishes a synchronous result (including empty output) from a missing receipt.
func readInflightReceipt(result, content json.RawMessage) (inflightReceipt, error) {
	var receipt inflightReceipt
	if err := receipt.readStructured(result); err != nil {
		return receipt, err
	}
	blocks, err := inflightContentBlocks(content)
	if err != nil {
		return receipt, err
	}
	for _, block := range blocks {
		if block.Type == "text" && block.Text != nil {
			if err := receipt.addText(*block.Text); err != nil {
				return receipt, err
			}
		}
	}
	if receipt.taskID == "" && len(receipt.output) == 0 {
		return receipt, errors.New("no result evidence in Claude Bash receipt")
	}
	return receipt, nil
}

// readStructured extracts the background task ID and either output stream from an owned Bash result.
func (r *inflightReceipt) readStructured(raw json.RawMessage) error {
	if len(raw) == 0 || raw[0] != '{' {
		return nil
	}
	var result struct {
		TaskID string  `json:"backgroundTaskId"`
		Stdout *string `json:"stdout"`
		Stderr *string `json:"stderr"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode Claude Bash receipt: %w", err)
	}
	r.taskID = result.TaskID
	for _, stream := range []*string{result.Stdout, result.Stderr} {
		if stream != nil {
			r.output = append(r.output, *stream)
		}
	}
	return nil
}

// addText checks the client-generated task ID against any identity already supplied for this call.
func (r *inflightReceipt) addText(text string) error {
	r.output = append(r.output, text)
	match := backgroundReceiptID.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	if r.taskID != "" && r.taskID != match[1] {
		return errors.New("conflicting background task IDs in Claude Bash receipt")
	}
	r.taskID = match[1]
	return nil
}

// confirmLaunches accepts a service start line only for a name requested by the matching Bash call.
func (w *inflightTranscript) confirmLaunches(units, output []string) {
	for _, text := range output {
		for offset := 0; offset < len(text); {
			line, _, _ := strings.Cut(text[offset:], "\n")
			offset += len(line) + 1
			w.confirmStartLine(units, strings.TrimSuffix(line, "\r"))
		}
	}
}

// confirmStartLine matches the literal name with or without systemd's default service suffix.
func (w *inflightTranscript) confirmStartLine(units []string, line string) {
	match := unitStartReceipt.FindStringSubmatch(line)
	if match == nil {
		return
	}
	name := strings.TrimSuffix(match[1], ".service")
	for _, unit := range units {
		if name == strings.TrimSuffix(unit, ".service") {
			w.confirmUnit(unit)
		}
	}
}
