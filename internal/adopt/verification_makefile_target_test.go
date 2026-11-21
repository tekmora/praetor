package adopt

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/util"
)

// End to end: a Makefile whose only mention of verify-all is a variable assignment owns no
// verify-all rule, so adoption appends its own targets instead of preserving and certifying a
// rule that make cannot run. Seven of the eight assignment forms of issue #304 are among the rows.
// The eighth, "verify-all != date +%H:%M", declares no rule either, but Make expands a "!="
// command's output as makefile text wherever the variable is expanded, so adoption leaves that
// file to review (TestAdoptionDocumentationGateRefusesBareExpansion).
//
// Adoption decides through the shared reader (util.MakefileMayDefineTarget), whose table tests
// are in internal/util/makefile_target_test.go: the preserved verdict is that reader's answer for
// every row. The editors step reads the adopted Makefile through the same reader, after the
// Makefile step, so the editor files of every row offer the verify-all rule that now exists.
func TestVerificationAssignmentIsNotAPreservedTarget(t *testing.T) {
	step := chainAdoptSteps(reconcileMakefile, reconcileEditors)
	for index, tc := range []struct {
		name, makefile string
		preserved      bool
	}{
		{"assignment", "verify-all := $(MAKE) -C build check\nall:\n\t@echo original\n", false},
		{"override-assignment", "override verify-all := $(MAKE) -C build check\nall:\n\t@echo original\n", false},
		{"posix-assignment", "verify-all ::= x\nall:\n\t@echo original\n", false},
		{"escaped-assignment", "verify-all :::= x\nall:\n\t@echo original\n", false},
		{"value-colon-assignment", "verify-all = docker run --rm ci:latest check\nall:\n\t@echo original\n", false},
		{"conditional-value-colon", "verify-all ?= a:b\nall:\n\t@echo original\n", false},
		{"appending-value-colon", "verify-all += x:y\nall:\n\t@echo original\n", false},
		{"target-specific-variable", "verify-all: CFLAGS := -g\nall:\n\t@echo original\n", false},
		{"value-names-target", "HELP = verify-all: run every gate\nall:\n\t@echo original\n", false},
		{"rule", "verify-all:\n\t@echo claimed\n", true},
		{"rule-with-help-comment", "verify-all: ## run gates (FAST=1)\n\t@echo claimed\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertVerificationAssignmentRow(t, tc.name, tc.makefile, tc.preserved, index == 0, step)
		})
	}
}

func assertVerificationAssignmentRow(t *testing.T, name, makefile string, preserved, whole bool, step adoptStep) {
	t.Helper()
	if shared := util.MakefileMayDefineTarget(makefile, verificationTarget); shared != preserved {
		t.Fatalf("the shared Makefile reader finds an owned verify-all = %v, want %v", shared, preserved)
	}
	root := newTestRepo(t, name)
	mustWrite(t, filepath.Join(root, "go.mod"), "module fixture\n")
	mustWrite(t, filepath.Join(root, "Makefile"), makefile)
	// The first fixture runs a whole adoption; the others run the makefile and editors steps
	// on the prepared session (#1381).
	report, err := adoptOrStep(t, AdoptOptions{Path: root, Profile: "framework", LockSourceRoot: newAdoptLockSource(t)}, whole, step)
	if err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, filepath.Join(root, "Makefile"))
	if tasks := mustRead(t, filepath.Join(root, ".vscode", "tasks.json")); !strings.Contains(tasks, `"make verify-all"`) {
		t.Fatalf("the editor tasks do not offer the verify-all rule the adopted Makefile declares: %s", tasks)
	}
	if preserved {
		assertPreservedVerificationRow(t, makefile, got, report.Verification)
		return
	}
	assertDeclaredVerificationRow(t, got, report.Verification)
}

func assertPreservedVerificationRow(t *testing.T, makefile, got string, plan *VerificationPlan) {
	t.Helper()
	want, mergeErr := mergeDocumentationMakefile(makefile, false)
	if mergeErr != nil {
		t.Fatal(mergeErr)
	}
	if plan.Status != verificationPreserved || got != want {
		t.Fatalf("custom rule not preserved: %+v %q", plan, got)
	}
}

func assertDeclaredVerificationRow(t *testing.T, got string, plan *VerificationPlan) {
	t.Helper()
	if plan.Status != verificationDeclared {
		t.Fatalf("assignment certified as a custom gate: %+v", plan)
	}
	if !strings.Contains(got, "\nverify-all:\n") || !strings.Contains(got, "@echo original") {
		t.Fatalf("declared verify-all not appended beside the existing recipes: %q", got)
	}
	for _, command := range plan.Test {
		if strings.Join(command, " ") == "make verify-all" {
			t.Fatalf("plan tests a preserved rule that does not exist: %+v", plan)
		}
	}
}

// The appended block skips a helper target the project already declares. A variable of the same
// name declares nothing, so compile-context and audit must still be appended; without them the
// appended verify-all recipe references prerequisites make cannot build. The rows that discriminate
// are value-colon and target-variable, which the "first colon wins" reader took for rules, and
// help-comment, which the target-specific-variable guard took for an assignment; the plain ":="
// rows are regression cover, correct in every generation of the reader.
func TestAppendedHelperTargetsIgnoreVariableAssignments(t *testing.T) {
	plan := &VerificationPlan{Status: verificationDeclared}
	for name, tc := range map[string]struct {
		existing string
		want     bool
	}{
		"assignment":        {"compile-context := x\naudit := y\nall:\n\t@echo original\n", true},
		"override-variable": {"override compile-context := x\noverride audit := y\n", true},
		"value-colon":       {"compile-context = go run ./x:latest\naudit = ci:audit\n", true},
		"export-directive":  {"export compile-context: x\nunexport audit: y\n", true},
		"target-variable":   {"compile-context: CFLAGS := -g\naudit: CFLAGS := -g\n", true},
		"rule":              {"compile-context:\n\t@echo c\naudit:\n\t@echo a\n", false},
		"help-comment": {"compile-context: dep ## compile (X=1)\n\t@echo c\n" +
			"audit: dep ## audit (Y=2)\n\t@echo a\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := appendVerificationTargets(tc.existing, plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"compile-context", "audit"} {
				if strings.Contains(got, "\n"+target+":\n\t@$(PRAETORCTL)") != tc.want {
					t.Fatalf("appended %s target = %v, want %v: %q", target, !tc.want, tc.want, got)
				}
			}
		})
	}
}
