// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/testsupport"
	"github.com/cordanaLLM/praetor/internal/util"
)

// admissionExecutableText is the rule-masked command Python passes to heavy-step admission.
func admissionExecutableText(t *testing.T, command string) string {
	t.Helper()
	segments, err := commandSegments(command)
	if err != nil {
		t.Fatalf("commandSegments(%q): %v", command, err)
	}
	text := command
	if len(segments) > 0 && segments[0].raw != "" {
		text = segments[0].raw
	}
	return joinLineContinuations(text)
}

// TestEvasionQuotedCommitOptionAdmissionText proves admission-readable text for quoted commit options.
func TestEvasionQuotedCommitOptionAdmissionText(t *testing.T) {
	for _, command := range []string{
		`git commit "-m" "$message"`,
		`git commit '-m' "$message"`,
		`git commit -"m" docs`,
	} {
		t.Run(command, func(t *testing.T) {
			text := admissionExecutableText(t, command)
			if _, ok := hiss.ShellCode(text, admissionMaxLines); !ok {
				t.Fatalf("admission text unreadable: %q", text)
			}
		})
	}
}

// engineAdmissionTexts captures the actual engine guard's delegation without loading host settings.
func engineAdmissionTexts(t *testing.T, command string) []string {
	t.Helper()
	const program = `import json, runpy, sys
audit = runpy.run_path(sys.argv[1])["audit_command"]
texts = []
audit.__globals__["check_admission"] = lambda text: texts.append(text) is None
if not audit(json.load(sys.stdin)):
    sys.exit(1)
json.dump(texts, sys.stdout)
`
	input, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	ctx := oracleContext(t, testsupport.DeadlineContext(t), guardEnvironment(), input)
	result, err := util.RunCommandBytes(ctx, "", testsupport.PythonInterpreter(t), util.MaxCommandOutputBytes,
		"-I", "-B", "-c", program, pythonGuard)
	if err != nil {
		t.Fatalf("capture engine admission text: %v: %s", err, result.Stderr)
	}
	var texts []string
	if err := json.Unmarshal(result.Stdout, &texts); err != nil {
		t.Fatalf("decode engine admission text: %v", err)
	}
	if len(texts) == 0 {
		t.Fatal("engine guard did not delegate to admission")
	}
	return texts
}

// judgeAdmissionTexts replays each delegated source against the engine's admission checker.
func judgeAdmissionTexts(t *testing.T, texts []string) Verdict {
	t.Helper()
	for _, text := range texts {
		verdict, err := CheckAdmission(config.AdmissionSettings{Enforce: true}, text)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Outcome != Allow {
			return verdict
		}
	}
	return Verdict{Outcome: Allow}
}

// TestEvasionHereDocumentAdmissionText checks data masking and executable stdin delegation.
func TestEvasionHereDocumentAdmissionText(t *testing.T) {
	for _, tc := range []struct {
		name, command, body, suffix string
		lines                       int
		deny                        bool
	}{
		{"dotted delimiter", "cat <<DOC.txt\nbody\nDOC.txt\ngit commit -m docs", "body", "git commit -m", 4, false},
		{"opener comment", "cat <<'EOF' # it's a note\nO'Brien <draft>\nEOF", "O'Brien <draft>", "", 3, false},
		{"leading redirect", ">\"out\\\nput\" cat <<'EOF'\nO'Brien <draft>\nEOF", "O'Brien <draft>", "", 3, false},
		{"literal commit text", "cat <<'EOF' > notes.txt\ngit commit -n -m x\nEOF", "git commit -n -m x", "", 3, false},
		{"literal test text", "cat <<'EOF' > notes.txt\nO'Brien wrote \"go test ./...\"\nEOF", "O'Brien wrote", "", 3, false},
		{"shell reader", "sh <<'EOF'\ngo test ./...\nEOF", "go test ./...", "", 3, true},
		{"downstream shell reader", "cat <<'EOF' | sh\ngo test ./...\nEOF", "go test ./...", "", 3, true},
		{"unquoted shell reader", "bash <<EOF\ngo test ./...\nEOF", "go test ./...", "", 3, true},
		{"data document substitution", "cat <<EOF\n$(go test ./...)\nEOF", "go test ./...", "", 3, true},
		{"shell here-string", `bash <<< 'go test ./...'`, "go test ./...", "bash", 1, true},
		{"data here-string", `cat <<< 'go test ./...'`, "go test ./...", "cat", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			texts := engineAdmissionTexts(t, tc.command)
			if got := strings.Count(texts[0], "\n") + 1; got != tc.lines {
				t.Errorf("parent source has %d lines, want %d: %q", got, tc.lines, texts[0])
			}
			if strings.Contains(texts[0], tc.body) || !strings.HasSuffix(strings.TrimSpace(texts[0]), tc.suffix) {
				t.Errorf("unexpected parent source: %q", texts[0])
			}
			verdict := judgeAdmissionTexts(t, texts)
			if tc.deny {
				if !strings.Contains(strings.Join(texts[1:], "\n"), tc.body) {
					t.Errorf("executable body missing from admission sources: %q", texts)
				}
				requireDeniedContaining(t, tc.command, verdict, "heavy step needs host admission:", "--label go-test")
			} else if verdict.Outcome != Allow {
				t.Errorf("data document refused: %s", verdict.Reason)
			}
		})
	}
}

// TestEvasionHereStringAdmission checks literal stdin through the enforcing Go policy.
func TestEvasionHereStringAdmission(t *testing.T) {
	goPolicy, err := BuildPolicy(config.HookSettings{Admission: config.AdmissionSettings{Enforce: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reader string
		deny   bool
	}{
		{"bash", true},
		{"cat", false},
	} {
		t.Run(tc.reader, func(t *testing.T) {
			command := tc.reader + " <<< 'go test ./...'"
			verdict := goPolicy.Command(command)
			if tc.deny {
				requireDeniedContaining(t, command, verdict, "heavy step needs host admission:", "--label go-test")
			} else if verdict.Outcome != Allow {
				t.Errorf("data here-string refused: %s", verdict.Reason)
			}
		})
	}
}

// TestDataOffsetQuotedWholeOption checks raw-length masking for fully quoted commit options.
func TestDataOffsetQuotedWholeOption(t *testing.T) {
	const word = `"-m"`
	s := &shellSpans{gitCommand: "commit"}
	if offset := s.dataOffset(word); offset != len(word) {
		t.Fatalf("dataOffset(%q)=%d want raw length %d", word, offset, len(word))
	}
	s = &shellSpans{gitCommand: "commit"}
	if s.dataOffset(`"-mdocs"`) >= 0 {
		t.Fatal("attached quoted option value must stay refused")
	}
}

// TestDataOffsetQuotedWholeOptionMutant proves decoded-length masking leaves admission text unreadable.
func TestDataOffsetQuotedWholeOptionMutant(t *testing.T) {
	const command = `git commit "-m" "$message"`
	text := admissionExecutableText(t, command)
	decoded := len(shellDataOptionPattern.FindString(dataOptionWord(`"-m"`)))
	if decoded >= len(`"-m"`) {
		t.Fatal("mutant offset must be shorter than the raw option word")
	}
	quoted := strings.Index(command, `"-m"`)
	if quoted < 0 {
		t.Fatal("fixture command lacks quoted -m option")
	}
	mutant := []byte(text)
	for index := quoted + decoded; index < quoted+len(`"-m"`); index++ {
		mutant[index] = ' '
	}
	if _, ok := hiss.ShellCode(string(mutant), admissionMaxLines); ok {
		t.Fatal("decoded offset mask must leave admission text unreadable")
	}
}
