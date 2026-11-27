// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/hiss"
)

// portabilityWorkflow is the engine's platform matrix, read from the repository root.
var portabilityWorkflow = filepath.Join("..", "..", ".github", "workflows", "portability.yml")

// halvesProblem reports how a workflow or step departs from running the package held in the shell
// variable pkg in two halves under the 30-minute bound: one go test with -run "$half", one with
// -skip "$half" (the same pattern, so every test runs exactly once), and the package left out of
// the main run. "" when every test-running job holds that shape.
func halvesProblem(workflow, pkg, half string) string {
	if spec, err := ghworkflow.Parse([]byte(workflow)); err == nil && len(spec.Jobs) > 0 {
		for _, jobID := range []string{"harness", "windows-shard"} {
			job, ok := spec.Jobs[jobID]
			if !ok {
				return "missing job " + jobID
			}
			step, found := findJobStep(job, "Test Every Package")
			if !found {
				return jobID + ": no Test Every Package step"
			}
			if problem := stepHalvesProblem(step.Run, pkg, half); problem != "" {
				return jobID + ": " + problem
			}
		}
		return ""
	}
	return stepHalvesProblem(workflow, pkg, half)
}

func findJobStep(job ghworkflow.Job, name string) (ghworkflow.Step, bool) {
	for i := 0; i < len(job.Steps) && i < ghworkflow.MaxStepsPerJob; i++ {
		if job.Steps[i].Name == name {
			return job.Steps[i], true
		}
	}
	return ghworkflow.Step{}, false
}

func stepHalvesProblem(step, pkg, half string) string {
	m := regexp.MustCompile(regexp.QuoteMeta(half) + `='([^']+)'`).FindStringSubmatch(step)
	if m == nil {
		return "no " + half + " pattern"
	}
	if _, err := regexp.Compile(m[1]); err != nil {
		return "the " + half + " pattern does not compile: " + err.Error()
	}
	source, ok := hiss.WorkflowShellCommandSource(step, maxTimeoutWorkflowLines)
	if !ok {
		return "unreadable shell run script or shell reader bound"
	}
	for _, args := range []string{
		`"${packages[@]##-*}"`,
		`"${adopt##-*}"`,
		`-run "$` + half + `" "${` + pkg + `##-*}"`,
		`-skip "$` + half + `" "${` + pkg + `##-*}"`,
	} {
		want := `go test -json -timeout 30m ` + args
		expected := strings.Fields(want)
		count := 0
		for _, command := range source.Commands {
			words := command.Words
			if halvesCommandHasPrefix(expected, len(words), func(i int) string { return words[i].Text }) {
				count++
			}
		}
		if count != 1 {
			return "not exactly one " + want
		}
	}
	if !strings.Contains(step, `-e "$`+pkg+`"`) {
		return "the main run does not leave out $" + pkg
	}
	return ""
}

// halvesCommandHasPrefix compares the expected words with the start of a command.
func halvesCommandHasPrefix(expected []string, wordCount int, wordAt func(int) string) bool {
	// Admit the literal command wrapper, not arbitrary prefixes or its options.
	start := 0
	if wordCount > 0 && wordAt(0) == "command" {
		start = 1
	}
	if wordCount-start < len(expected) {
		return false
	}
	for i, word := range expected {
		if wordAt(start+i) != word {
			return false
		}
	}
	return true
}

func TestPortability_CommentCannotSupplyPackageSelection(t *testing.T) {
	const head = `go test -json -timeout 30m`
	const main = head + ` "${packages[@]##-*}"`
	const adopt = head + ` "${adopt##-*}"`
	step := strings.Join([]string{
		`cli_half='^TestA$'`,
		`grep -v -e "$cli" input`,
		main,
		adopt,
		head + ` -run "$cli_half" "${cli##-*}"`,
		head + ` -skip "$cli_half" "${cli##-*}"`,
	}, "\n")
	if problem := stepHalvesProblem(step, "cli", "cli_half"); problem != "" {
		t.Fatalf("valid step: %s", problem)
	}
	if problem := stepHalvesProblem(strings.Replace(step, main, "command "+main, 1), "cli", "cli_half"); problem != "" {
		t.Errorf("command-prefixed main invocation: %s", problem)
	}
	for _, replacement := range []string{"# command " + main + "\n" + head, "echo command " + main} {
		mutant := strings.Replace(step, main, replacement, 1)
		if got, want := stepHalvesProblem(mutant, "cli", "cli_half"), "not exactly one "+main; got != want {
			t.Errorf("replacement %q: got %q, want %q", replacement, got, want)
		}
	}
	for _, command := range []string{main, adopt} {
		mutant := strings.Replace(step, command, "# "+command+"\n"+head, 1)
		if got, want := stepHalvesProblem(mutant, "cli", "cli_half"), "not exactly one "+command; got != want {
			t.Errorf("comment-only %s: got %q, want %q", command, got, want)
		}
	}
}

func readPortability(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(portabilityWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Positive (engine-main-452c74e3c-windows-timeout-20261019): cmd/standardsctl passed the
// 30-minute go test bound on Windows with no test hanging, so the matrix runs it in two halves.
func TestPortability_LongestPackageRunsInHalves(t *testing.T) {
	if problem := halvesProblem(readPortability(t), "cli", "cli_half"); problem != "" {
		t.Fatalf("%s: %s", portabilityWorkflow, problem)
	}
}

// Negative: a step that drops the -skip half (those tests never run), keeps the package in the
// main run (it runs whole again), or loses the pattern is refused.
func TestPortability_Negative_PlantedHalvesAreRefused(t *testing.T) {
	step := readPortability(t)
	planted := map[string]string{
		"no -skip half":         strings.Replace(step, `-skip "$cli_half"`, `-run "$cli_half"`, 1),
		"package in main run":   strings.Replace(step, ` -e "$cli"`, "", 1),
		"no pattern":            strings.Replace(step, `cli_half='`, `cli_part='`, 1),
		"raised timeout on one": strings.Replace(step, `-timeout 30m -run "$cli_half"`, `-timeout 60m -run "$cli_half"`, 1),
	}
	for name, text := range planted {
		if text == step {
			t.Fatalf("%s: the planted change did not apply", name)
		}
		if halvesProblem(text, "cli", "cli_half") == "" {
			t.Errorf("%s: a broken step passed", name)
		}
	}
}

// cliTestNames lists the top-level Test functions of cmd/standardsctl's test files.
func cliTestNames(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "cmd", "standardsctl", "*_test.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("list cmd/standardsctl tests: %v (%d files)", err, len(files))
	}
	var names []string
	fset := token.NewFileSet()
	for index := 0; index < len(files) && index < 4096; index++ {
		file, err := parser.ParseFile(fset, files[index], nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				names = append(names, fn.Name.Name)
			}
		}
	}
	return names
}

// Boundary: the pattern splits cmd/standardsctl's tests into two non-empty halves, so neither
// invocation runs nothing and none runs everything.
func TestPortability_Boundary_HalvesAreBothNonEmpty(t *testing.T) {
	m := regexp.MustCompile(`cli_half='([^']+)'`).FindStringSubmatch(readPortability(t))
	if m == nil {
		t.Fatal("no cli_half pattern")
	}
	pattern := regexp.MustCompile(m[1])
	matched, other := 0, 0
	for _, name := range cliTestNames(t) {
		if pattern.MatchString(name) {
			matched++
		} else {
			other++
		}
	}
	if matched == 0 || other == 0 {
		t.Fatalf("pattern %q splits cmd/standardsctl's tests %d / %d; both halves must hold tests", m[1], matched, other)
	}
}

// TestPortability_PlantedPackageSelection requires the main and adopt command in each matrix job to select its package.
func TestPortability_PlantedPackageSelection(t *testing.T) {
	workflow := readPortability(t)
	for _, operand := range []string{`"${packages[@]##-*}"`, `"${adopt##-*}"`} {
		const prefix = `go test -json -timeout 30m `
		command := prefix + operand
		first, last := strings.Index(workflow, command), strings.LastIndex(workflow, command)
		if first < 0 || last <= first {
			t.Fatalf("expected %s in both test jobs", command)
		}
		for _, at := range []int{first, last} {
			mutant := workflow[:at] + prefix + workflow[at+len(command):]
			if problem := halvesProblem(mutant, "cli", "cli_half"); problem == "" {
				t.Errorf("dropping %s at %d left package selection green", operand, at)
			}
		}
	}
}
