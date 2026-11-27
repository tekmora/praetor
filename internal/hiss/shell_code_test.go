// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package hiss

import (
	"reflect"
	"strings"
	"testing"
)

// Positive: code stays, quoted text and comments are blanked, a here-document body comes back
// as empty lines, and a backquoted substitution is written as $(...).
func TestShellCode_Positive_BlanksQuotesCommentsAndBodies(t *testing.T) {
	lines, ok := ShellCode("echo \"make test\" && go vet ./... # make\ncat <<'EOF'\nmake all\nEOF\nx=`go env GOPATH`", 10)
	want := []string{`echo "" && go vet ./... `, "cat <<", "", "", "x=$(go env GOPATH)"}
	if !ok || !reflect.DeepEqual(lines, want) {
		t.Fatalf("ShellCode = %q, %v; want %q", lines, ok, want)
	}
}

// Negative: an open quote, a here-document without its closing line and a script over the
// line bound are not readable.
func TestShellCode_Negative_UnreadableScripts(t *testing.T) {
	for name, script := range map[string]string{
		"open quote":        `echo "unclosed`,
		"open here-doc":     "cat <<EOF\nmake all",
		"over bound":        strings.Repeat("true\n", 10),
		"unreadable delim":  "cat <<E$X\nbody\nE$X",
		"open substitution": "x=$(go env",
	} {
		if lines, ok := ShellCode(script, 5); ok {
			t.Errorf("%s read as %q", name, lines)
		}
	}
}

// Boundary: the empty script is one empty line, a script at exactly the bound is read, and a
// CRLF script reads like its LF form.
func TestShellCode_Boundary_EmptyBoundAndCRLF(t *testing.T) {
	if lines, ok := ShellCode("", 1); !ok || !reflect.DeepEqual(lines, []string{""}) {
		t.Fatalf("empty script = %q, %v", lines, ok)
	}
	if _, ok := ShellCode("a\nb\nc", 3); !ok {
		t.Fatal("a script at the line bound was refused")
	}
	crlf, ok1 := ShellCode("make a\r\nmake b", 5)
	lf, ok2 := ShellCode("make a\nmake b", 5)
	if !ok1 || !ok2 || !reflect.DeepEqual(crlf, lf) {
		t.Fatalf("CRLF %q vs LF %q", crlf, lf)
	}
}

// These cases exercise comment boundaries, including the former forge scanner's
// quote, escape and word-splice fixtures.
var shellCodeContinuationCases = []struct {
	name   string
	script string
	want   []string
}{
	{"comment at word start", "#x", []string{""}},
	{"hash at word start with nothing after it", "#", []string{""}},
	{"hash after splice is part of a word", "a\\\n#x", []string{"a#x", ""}},
	{"hash after blank", "echo a #c", []string{"echo a "}},
	{"hash inside word", "a#b", []string{"a#b"}},
	{"hash after escaped blank", "a\\ #", []string{"a_#"}},
	{"continued hash payload", "a\\\n#x\\\ntrue", []string{"a#xtrue", "", ""}},
	{"comment line ends before next command", "#x\\\ntrue", []string{"", "true"}},
	{"inline comment ends before next command", "echo a #c\\\ntrue", []string{"echo a ", "true"}},
	{"end without a comment", "echo a\\\n b", []string{"echo a b", ""}},
	{"empty line", "", []string{""}},
	{"command without continuation", "echo a", []string{"echo a"}},
	{"hash in double quote", "NOTE=\"a \\\n# b\" go test \\\n-timeout 45m", []string{"NOTE=\"\" go test -timeout 45m", "", ""}},
	{"hash after double quote", "NOTE=\"a \\\n# b\" go test #c\\\ntrue", []string{"NOTE=\"\" go test ", "", "true"}},
	{"hash after single quote", "echo 'x \\\n#y' #c\\\ntrue", []string{"echo '' ", "", "true"}},
	{"hash after substitution", "NOTE=$(printf x)#tag go test \\\n-timeout 45m", []string{"NOTE=$(printf x)#tag go test -timeout 45m", ""}},
	{"hash after subshell", "(echo x)#tag\\\ntrue", []string{"(echo x)", "true"}},
	{"empty splice before a hash", "echo a\\\n\\\n#b", []string{"echo a#b", "", ""}},
	{"even backslash pair", "echo a\\\\\n#b", []string{"echo a_", ""}},
	{"splice inside operator", "a &\\\n& b", []string{"a && b", ""}},
	{"comment ends before empty splice", "echo x #c\\\n\\\nnext", []string{"echo x ", "next", ""}},
}

// TestShellCode_ContinuationBoundaries pins ShellCode behavior across line continuations, splices, and comment boundaries.
func TestShellCode_ContinuationBoundaries(t *testing.T) {
	for _, tc := range shellCodeContinuationCases {
		t.Run(tc.name, func(t *testing.T) {
			lines, ok := ShellCode(tc.script, 3)
			if !ok || !reflect.DeepEqual(lines, tc.want) {
				t.Fatalf("ShellCode = %q, %v; want %q", lines, ok, tc.want)
			}
		})
	}
}

// TestShellCodeCommands_SourceWords tests extraction of command words, source text, and values across substitutions and continuations.
func TestShellCodeCommands_SourceWords(t *testing.T) {
	script := "NOTE=$(printf x)#tag go test -time\\\nout \"45m\" # -timeout 99m\\\ntrue"
	commands, ok := ShellCodeCommands(script, 3, nil)
	want := []ShellCodeCommand{
		{Line: 0, Words: []ShellCodeWord{
			{Code: "printf", Text: "printf", Value: "printf", Span: [2]int{7, 13}},
			{Code: "x", Text: "x", Value: "x", Span: [2]int{14, 15}},
		}},
		{Line: 0, Prefix: []ShellCodeWord{
			{Code: "NOTE=___________#tag", Text: "NOTE=$(printf x)#tag", Value: "NOTE=$(printf x)#tag", Span: [2]int{0, 20}},
		}, Words: []ShellCodeWord{
			{Code: "go", Text: "go", Value: "go", Span: [2]int{21, 23}},
			{Code: "test", Text: "test", Value: "test", Span: [2]int{24, 28}},
			{Code: "-timeout", Text: "-timeout", Value: "-timeout", Span: [2]int{29, strings.Index(script, " \"45m\"")}},
			{Code: "\"___\"", Text: "\"45m\"", Value: "45m", Span: [2]int{strings.Index(script, "\"45m\""), strings.Index(script, " # -timeout")}},
		}},
		{Line: 2, Words: []ShellCodeWord{{Code: "true", Text: "true", Value: "true", Span: [2]int{len(script) - 4, len(script)}}}},
	}
	if !ok || !reflect.DeepEqual(commands, want) {
		t.Fatalf("ShellCodeCommands = %+v, %v; want %+v", commands, ok, want)
	}
}

// TestShellCodeCommands_QuotedContinuationSource verifies retention or removal of spliced newlines within single and double quotes.
func TestShellCodeCommands_QuotedContinuationSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"single quote preserves splice", "echo '45\\\nm'", "'45\\\nm'"},
		{"double quote removes splice", "echo \"45\\\nm\"", "\"45m\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands, ok := ShellCodeCommands(tc.line, 2, nil)
			if !ok || len(commands) != 1 || len(commands[0].Words) != 2 || commands[0].Words[1].Text != tc.want {
				t.Fatalf("ShellCodeCommands = %+v, %v; want one argument with source %q", commands, ok, tc.want)
			}
		})
	}
}

// TestShellCodeCommands_Bounds pins upper limits and rejection of unclosed constructs and command counts exceeding bounds.
func TestShellCodeCommands_Bounds(t *testing.T) {
	for _, script := range []string{
		"echo a\\\n\\\n#b",
		"echo 'unclosed",
		strings.Repeat("true;", maxShellCommands) + "true",
	} {
		if commands, ok := ShellCodeCommands(script, 2, nil); ok {
			t.Errorf("ShellCodeCommands(%q) read %d commands; want unreadable", script[:min(len(script), 30)], len(commands))
		}
	}
	atBound := strings.Repeat("true;", maxShellCommands-1) + "true"
	if commands, ok := ShellCodeCommands(atBound, 1, nil); !ok || len(commands) != maxShellCommands {
		t.Fatalf("read %d commands, %v; want the %d-command boundary", len(commands), ok, maxShellCommands)
	}
}

// TestShellCodeCommands_OpaqueSourceSpans verifies handling of opaque literal spans and rejection of invalid span ranges.
func TestShellCodeCommands_OpaqueSourceSpans(t *testing.T) {
	script := "$(VAR) 'x'\\y; true"
	commands, ok := ShellCodeCommands(script, 1, map[int]int{0: len("$(VAR)")})
	if !ok || len(commands) != 2 || len(commands[0].Words) != 2 {
		t.Fatalf("ShellCodeCommands = %+v, %v; want an opaque command and true", commands, ok)
	}
	words := commands[0].Words
	if words[0].Code != "______" || words[0].Value != "$(VAR)" || words[1].Value != "xy" {
		t.Fatalf("words = %+v; want opaque $(VAR) and unquoted xy", words)
	}
	for _, spans := range []map[int]int{{0: len(script) + 1}, {0: 6, 3: 7}} {
		if _, ok := ShellCodeCommands(script, 1, spans); ok {
			t.Errorf("accepted invalid opaque spans %v", spans)
		}
	}
}
