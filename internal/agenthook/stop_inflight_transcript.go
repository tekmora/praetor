// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// inflightTranscript tracks background tool-use IDs until their receipts identify the actual task IDs.
type inflightTranscript struct {
	session      string
	units        []string
	calls        map[string]int
	tasks        map[string]bool
	sequence     int
	ended        map[string]int
	launchNotice string
}

// inflightBlock projects only the Claude tool and text fields used by the Stop check.
type inflightBlock struct {
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	ID        string          `json:"id"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	Text      string          `json:"text"`
}

// inflightRow keeps tool results opaque because Claude tools return different shapes.
type inflightRow struct {
	inflightBlock
	SessionID     string          `json:"sessionId"`
	Sidechain     bool            `json:"isSidechain"`
	ToolUseResult json.RawMessage `json:"toolUseResult"`
	Operation     string          `json:"operation"`
	Message       struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	Origin struct {
		Kind string `json:"kind"`
	} `json:"origin"`
}

const maxInflightBlocks = 1024

var backgroundReceiptID = regexp.MustCompile(`^Command running in background with ID: ([A-Za-z0-9_-]+)(?:[.[:space:]]|$)`)

// visit consumes one JSONL record in order. Sidechain and foreign-session work cannot keep this session awake.
func (w *inflightTranscript) visit(line []byte) error {
	if len(line) > maxClaudeTranscriptLineBytes {
		return errors.New("claude transcript row exceeds size limit")
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return nil
	}
	var row inflightRow
	if err := json.Unmarshal(line, &row); err != nil {
		return fmt.Errorf("decode Claude transcript row: %w", err)
	}
	if !row.inSession(w.session) {
		return nil
	}
	switch row.Type {
	case "queue-operation":
		return w.queuedNotification(&row)
	case "tool_use":
		return w.toolUse(row.inflightBlock)
	case "assistant", "user":
		return w.message(&row)
	}
	return nil
}

// inSession excludes subagent traffic and rows explicitly belonging to a different conversation.
func (row *inflightRow) inSession(session string) bool {
	return !row.Sidechain && (session == "" || row.SessionID == "" || session == row.SessionID)
}

// queuedNotification reads task envelopes already enqueued for delivery to the session.
func (w *inflightTranscript) queuedNotification(row *inflightRow) error {
	if row.Operation != "enqueue" || len(row.Content) == 0 || row.Content[0] != '"' {
		return nil
	}
	var text string
	if err := json.Unmarshal(row.Content, &text); err != nil {
		return err
	}
	return w.notifications(row.Origin.Kind, text)
}

// message applies each content block in the order recorded by the client.
func (w *inflightTranscript) message(row *inflightRow) error {
	blocks, err := inflightContentBlocks(row.Message.Content)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		if err := w.consume(row, block); err != nil {
			return err
		}
	}
	return nil
}

// inflightContentBlocks normalizes the two Claude content shapes and bounds the array before allocation.
func inflightContentBlocks(raw json.RawMessage) ([]inflightBlock, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		block := inflightBlock{Type: "text"}
		if err := json.Unmarshal(raw, &block.Text); err != nil {
			return nil, err
		}
		return []inflightBlock{block}, nil
	}
	if raw[0] != '[' {
		return nil, errors.New("expected Claude text or content blocks")
	}
	return decodeInflightBlockArray(raw)
}

// decodeInflightBlockArray checks the item bound before decoding each additional content block.
func decodeInflightBlockArray(raw json.RawMessage) ([]inflightBlock, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var blocks []inflightBlock
	for i := 0; i < maxInflightBlocks && decoder.More(); i++ {
		var block inflightBlock
		if err := decoder.Decode(&block); err != nil {
			return nil, fmt.Errorf("decode Claude content block: %w", err)
		}
		blocks = append(blocks, block)
	}
	if decoder.More() {
		return nil, errors.New("claude message exceeds content block limit")
	}
	return blocks, nil
}

// consume accepts launches from assistant tool use and receipts or terminal notifications from user messages.
func (w *inflightTranscript) consume(row *inflightRow, block inflightBlock) error {
	if row.Type == "assistant" {
		return w.toolUse(block)
	}
	switch block.Type {
	case "text":
		return w.notifications(row.Origin.Kind, block.Text)
	case "tool_result":
		return w.toolResult(row.ToolUseResult, block)
	}
	return nil
}

// toolUse records only explicit Bash background requests and literal user-unit launches.
func (w *inflightTranscript) toolUse(block inflightBlock) error {
	if block.Type != "tool_use" || !strings.EqualFold(block.Name, "Bash") {
		return nil
	}
	var input struct {
		Command    string `json:"command"`
		Background bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(block.Input, &input); err != nil {
		return fmt.Errorf("decode Claude Bash input: %w", err)
	}
	if input.Background {
		if err := w.startCall(block.ID); err != nil {
			return err
		}
	}
	if err := w.launches(input.Command); err != nil && w.launchNotice == "" {
		w.launchNotice = "In-flight unit check could not identify every launch: " + err.Error()
	}
	return nil
}

// startCall records when the background request starts, pending its task-ID receipt.
func (w *inflightTranscript) startCall(id string) error {
	if id == "" || len(id) > MaxCorrelationIDBytes {
		return errors.New("background Bash call missing a usable tool ID")
	}
	if len(w.calls)+len(w.tasks) >= maxInflightBlocks {
		return errors.New("claude background task count exceeds limit")
	}
	if len(w.calls) == 0 {
		clear(w.ended)
	}
	w.sequence++
	w.calls[id] = w.sequence
	return nil
}

// toolResult binds a task only to the matching background call. A synchronous or failed result retires the request.
func (w *inflightTranscript) toolResult(result json.RawMessage, block inflightBlock) error {
	start, requested := w.calls[block.ToolUseID]
	if !requested {
		return nil
	}
	delete(w.calls, block.ToolUseID)
	if block.IsError {
		return nil
	}
	id, err := backgroundTaskID(result, block.Content)
	if err != nil {
		return err
	}
	if id != "" && w.ended[id] < start {
		w.tasks[id] = true
	}
	return nil
}

// backgroundTaskID reads the structured Bash receipt, then the client-generated receipt text.
func backgroundTaskID(result, content json.RawMessage) (string, error) {
	var receipt struct {
		TaskID string `json:"backgroundTaskId"`
	}
	if len(result) > 0 && result[0] == '{' {
		if err := json.Unmarshal(result, &receipt); err != nil {
			return "", fmt.Errorf("decode Claude background receipt: %w", err)
		}
	}
	if receipt.TaskID != "" {
		return receipt.TaskID, nil
	}
	blocks, err := inflightContentBlocks(content)
	if err != nil {
		return "", err
	}
	for _, block := range blocks {
		if match := backgroundReceiptID.FindStringSubmatch(block.Text); block.Type == "text" && match != nil {
			return match[1], nil
		}
	}
	return "", nil
}

// notifications consumes consecutive terminal envelopes at the start of a user message, including older rows without origin.
func (w *inflightTranscript) notifications(origin, text string) error {
	if origin != "" && origin != "task-notification" {
		return nil
	}
	for i := 0; i <= maxInflightBlocks; i++ {
		body, ok := strings.CutPrefix(strings.TrimSpace(text), "<task-notification>")
		if !ok {
			return nil
		}
		body, rest, ok := strings.Cut(body, "</task-notification>")
		if !ok {
			return errors.New("incomplete Claude task-notification")
		}
		switch notificationField(body, "status") {
		case "completed", "failed", "killed":
			if err := w.finishTask(notificationField(body, "task-id"), notificationField(body, "tool-use-id")); err != nil {
				return err
			}
		}
		text = rest
	}
	return errors.New("claude task-notification count exceeds limit")
}

// finishTask remembers a completion that arrived between a background call and its task-ID receipt.
func (w *inflightTranscript) finishTask(task, call string) error {
	delete(w.tasks, task)
	delete(w.calls, task)
	delete(w.calls, call)
	if len(w.calls) == 0 {
		clear(w.ended)
		return nil
	}
	if w.ended == nil {
		w.ended = make(map[string]int)
	}
	if len(w.ended) >= maxInflightBlocks {
		return errors.New("unmatched Claude task-notification count exceeds limit")
	}
	w.ended[task] = w.sequence
	return nil
}

// notificationField reads one scalar from the notification header without interpreting its free-form summary.
func notificationField(body, tag string) string {
	header, _, _ := strings.Cut(body, "<summary>")
	_, rest, ok := strings.Cut(header, "<"+tag+">")
	if !ok {
		return ""
	}
	value, _, ok := strings.Cut(rest, "</"+tag+">")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}
