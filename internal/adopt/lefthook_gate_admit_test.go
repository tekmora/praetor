package adopt

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/gating"
	"github.com/cordanaLLM/praetor/internal/hisscatalog"
	"github.com/cordanaLLM/praetor/internal/util"
	"go.yaml.in/yaml/v3"
)

// mesonMarker is the root file of a Meson project: the gate runs no toolchain for it.
const mesonMarker = "project('demo', 'c')\n"

// strictGateRenderings are the renderings under testdata/lefthook whose pre-push gate ran without
// --admit-unsupported, one per language set, each with the markers of a repository detected as
// that set. The governance-only one is a Meson repository, the repository #648 reports.
var strictGateRenderings = []struct {
	fixture   string
	markers   map[string]string
	languages hisscatalog.Language
}{
	{"strict-gate-governance", map[string]string{"meson.build": mesonMarker}, 0},
	{"strict-gate-go", map[string]string{"go.mod": goModMarker}, hisscatalog.LanguageGo},
	{"strict-gate-rust", map[string]string{"Cargo.toml": cargoTOMLBody}, hisscatalog.LanguageRust},
	{"strict-gate-go-rust", map[string]string{"go.mod": goModMarker, "Cargo.toml": cargoTOMLBody}, lefthookJobLanguages},
}

// strictGateFixtureNames are the file names of one strict rendering, without and with the
// checkpoint jobs.
func strictGateFixtureNames(fixture string) []string {
	return []string{fixture + ".lefthook.yml", fixture + "-checkpoint.lefthook.yml"}
}

// Positive (#648): every rendering's pre-push gate job passes --admit-unsupported, spelled from the
// flag's own constant, and its header says a root with neither go.mod nor Cargo.lock is admitted
// without a receipt. Run against a recording stub, the line calls exactly those arguments.
func TestLefthookGate_Positive_PrePushGateAdmitsUnsupportedLanguages(t *testing.T) {
	for _, languages := range lefthookLanguageSets {
		for _, checkpoint := range []bool{false, true} {
			rendered := buildLefthookYAMLFor(lefthookShape{languages: languages}, checkpoint)
			var decoded map[string]any
			if err := yaml.Unmarshal([]byte(rendered), &decoded); err != nil {
				t.Fatalf("languages=%v checkpoint=%v: %v", languages, checkpoint, err)
			}
			if got := decodedJob(t, decoded, "pre-push", "gate")["run"]; got != lefthookGovernedCommand(prePushGateArgs) {
				t.Errorf("languages=%v checkpoint=%v: pre-push gate = %v", languages, checkpoint, got)
			}
			if !strings.Contains(rendered, "# gets no receipt: the job names the languages it could not verify and\n") {
				t.Errorf("languages=%v checkpoint=%v: the header does not state the admission", languages, checkpoint)
			}
		}
	}
	stubs, work := t.TempDir(), t.TempDir()
	log := filepath.Join(work, "calls.log")
	recordingStub(t, stubs, util.PraetorCLI, log, 0)
	if out, code := runHookLine(t, "sh", lefthookGovernedCommand(prePushGateArgs), stubs, work); code != 0 {
		t.Fatalf("gate hook line exited %d: %s", code, out)
	}
	if got := mustRead(t, log); !strings.HasSuffix(got, util.PraetorCLI+" gate run --path=. --"+gating.AdmitUnsupportedFlag+"\n") {
		t.Fatalf("calls = %q", got)
	}
}

// Positive: admit runs the resolved pinned engine and gate subcommand after --, even when the
// pin's cache path contains spaces and a different engine is on PATH.
func TestLefthookGate_Positive_PrePushGateRunsGateThroughAdmit(t *testing.T) {
	f := newEngineFixture(t)
	f.cache = filepath.Join(f.cache, "engine cache")
	directory := f.cached(enginePin)
	f.declare("gate.yml", "env:\n  PRAETOR_REF: "+enginePin+"\n")
	writeStub(t, f.stubs, util.PraetorCLI, "exit 99\n")
	writeStub(t, f.stubs, "uname", "printf '%s\\n' Linux\n")
	admitPassthroughStub(t, directory, util.LegacyCLI, f.log, 0)
	if out, code := f.runLine(generatedPrePushGate(t), "OS="); code != 0 {
		t.Fatalf("gate hook line exited %d: %s", code, out)
	}
	got := mustRead(t, f.log)
	pinned := filepath.Join(directory, util.LegacyCLI)
	if !strings.Contains(got, "admit --class push --local --label push-gate -- "+pinned+" gate run") {
		t.Fatalf("admit must run the pinned gate with the engine's default wait: %q", got)
	}
	if !strings.Contains(got, util.LegacyCLI+" gate run --path=. --"+gating.AdmitUnsupportedFlag) {
		t.Fatalf("inner gate subcommand not executed: %q", got)
	}
}

// admitPassthroughStub advertises push admission, logs every call and executes the argv after admit's --.
func admitPassthroughStub(t *testing.T, dir, name, log string, code int) {
	t.Helper()
	body := "set -eu\necho \"" + name + " $*\" >> '" + log + "'\n" +
		"case \"$1\" in\nadmit)\n  shift\n" +
		"  if [ \"$1\" = --help ]; then printf 'Usage of admit:\\n  -class string\\n' >&2; exit 0; fi\n" +
		"  while [ $# -gt 0 ]; do [ \"$1\" = \"--\" ] && shift && break; shift; done\n" +
		"  exec \"$@\"\n  ;;\nesac\nexit " + strconv.Itoa(code) + "\n"
	writeStub(t, dir, name, body)
}

// generatedPrePushGate returns the actual gate command from the generated Go hook.
func generatedPrePushGate(t *testing.T) string {
	t.Helper()
	rendered := buildLefthookYAMLFor(lefthookShape{languages: hisscatalog.LanguageGo}, false)
	var decoded map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &decoded); err != nil {
		t.Fatal(err)
	}
	command, ok := decodedJob(t, decoded, "pre-push", "gate")["run"].(string)
	if !ok {
		t.Fatal("generated gate has no run command")
	}
	return command
}

// TestReview2044GeneratedPrePushRunsOnNonUnix exercises the direct gate when the launcher cannot
// confirm the platform supports push slots.
func TestReview2044GeneratedPrePushRunsOnNonUnix(t *testing.T) {
	const engine = `case "$*" in
  "admit --help") printf 'Usage of admit:\n  -class string\n' >&2 ;;
  admit*) echo 'push slot: host push slot leases require Unix advisory file locks' >&2; exit 1 ;;
  "gate run --path=. --admit-unsupported") echo 'verified gate' ;;
  *) exit 2 ;;
esac
`
	for _, tc := range []struct{ name, osEnv, uname string }{
		{"Windows", "OS=Windows_NT", "printf '%s\\n' MINGW64_NT-10.0\n"},
		{"unknown uname", "OS=", "printf '%s\\n' unknown\n"},
		{"failed uname", "OS=", "printf '%s\\n' Linux\nexit 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEngineFixture(t)
			writeStub(t, f.stubs, "uname", tc.uname)
			writeStub(t, f.stubs, util.PraetorCLI, engine)
			out, code := f.runLine(generatedPrePushGate(t), tc.osEnv)
			if code != 0 || !strings.Contains(out, "verified gate") {
				t.Fatalf("direct gate: exit %d, output %q", code, out)
			}
		})
	}
}

// TestReview2044PrePushWithOlderEngine exercises both the resolved PATH engine and a pinned
// engine that lacks --class, even when a newer engine is installed on PATH.
func TestReview2044PrePushWithOlderEngine(t *testing.T) {
	const older = `case "$*" in
  "admit --help") printf 'Usage of admit:\n  -wait duration\n' >&2 ;;
  admit*) echo 'flag provided but not defined: -class' >&2; exit 1 ;;
  "gate run --path=. --admit-unsupported") echo 'verified old engine gate' ;;
  *) exit 2 ;;
esac
`
	for _, name := range []string{"PATH", "pin", "edited launcher"} {
		t.Run(name, func(t *testing.T) {
			f := newEngineFixture(t)
			if name == "pin" {
				directory := f.cached(enginePin)
				f.declare("gate.yml", "env:\n  PRAETOR_REF: "+enginePin+"\n")
				writeStub(t, f.stubs, util.PraetorCLI, "printf '  -class string\\n' >&2\nexit 2\n")
				writeStub(t, directory, util.LegacyCLI, older)
			} else {
				writeStub(t, f.stubs, util.PraetorCLI, older)
			}
			if name == "edited launcher" {
				mustWrite(t, filepath.Join(f.work, engineLauncherFile), "#!/bin/sh\nexec praetorctl \"$@\"\n# local edit\n")
			}
			writeStub(t, f.stubs, "uname", "printf '%s\\n' Linux\n")
			out, code := f.runLine(generatedPrePushGate(t), "OS=")
			if code != 0 || !strings.Contains(out, "verified old engine gate") {
				t.Fatalf("old engine gate: exit %d, output %q", code, out)
			}
		})
	}
}

// TestReview2044PreviousGoRenderingMigrates exercises the exact Go rendering from the parent
// commit with its original direct gate, then checks that a locally edited copy stays untouched.
func TestReview2044PreviousGoRenderingMigrates(t *testing.T) {
	previous := mustRead(t, "testdata/lefthook/before-push-slot-go-reuse.lefthook.yml")
	markers := map[string]string{"go.mod": goModMarker}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo, rep := adoptMarkedRepo(t, "previous-go-gate", markers, previous)
	reconciled := hasAction(rep, lefthookFile, actionReconcile)
	activated := fileExists(filepath.Join(repo, ".git", "hooks", preCommitHook))
	if !reconciled || !activated {
		t.Errorf("exact previous rendering: reconciled=%t activated=%t", reconciled, activated)
	}
	edited := previous + "# local edit\n"
	repo, rep = adoptMarkedRepo(t, "edited-previous-go-gate", markers, edited)
	retained := mustRead(t, filepath.Join(repo, lefthookFile)) == edited
	skipped := hasAction(rep, lefthookFile, actionSkip)
	activated = fileExists(filepath.Join(repo, ".git", "hooks", preCommitHook))
	if !retained || !skipped || activated {
		t.Errorf("locally edited previous rendering: retained=%t skipped=%t activated=%t", retained, skipped, activated)
	}
}

// Negative: a rendering whose pre-push gate refused every unsupported root is no current rendering
// for any language set. Unedited, it is an earlier Praetor rendering to migrate; with a local edit
// it is neither and is kept with a reason, like any configuration Praetor did not write. A failing
// gate still blocks the push through the rendered line.
func TestClassifyLefthookConfig_Negative_StrictPrePushGateIsNotCurrent(t *testing.T) {
	fixtures := readPriorLefthookFixtures(t)
	for _, rendering := range strictGateRenderings {
		for _, name := range strictGateFixtureNames(rendering.fixture) {
			data, ok := fixtures[name]
			if !ok {
				t.Fatalf("missing fixture %s", name)
			}
			if matchCurrentLefthook(data, lefthookShape{languages: rendering.languages}).found {
				t.Errorf("%s: a strict pre-push gate matched the current rendering", name)
			}
			if got := classifyLefthookConfig(data, lefthookShape{languages: rendering.languages}); got != (lefthookIdentity{prior: true}) {
				t.Errorf("%s: classified %+v, want an earlier rendering", name, got)
			}
			edited := append(append([]byte{}, data...), "# local edit\n"...)
			if got := classifyLefthookConfig(edited, lefthookShape{languages: rendering.languages}); got.prior || got.reason == "" {
				t.Errorf("%s: an edited copy classified %+v, want kept with a reason", name, got)
			}
		}
	}
	stubs, work := t.TempDir(), t.TempDir()
	recordingStub(t, stubs, util.PraetorCLI, filepath.Join(work, "calls.log"), 1)
	if _, code := runHookLine(t, "sh", lefthookGovernedCommand(prePushGateArgs), stubs, work); code == 0 {
		t.Fatal("a failing gate did not block the push")
	}
}

// Boundary: each strict rendering, with and without checkpoint jobs, migrates on a plain run in a
// repository of its own languages, a Meson repository included: a reconcile with no replace, so no
// --force and no backup, to the current rendering for those languages, which is then activated.
func TestAdopt_Boundary_StrictPrePushGateMigratesWithoutForce(t *testing.T) {
	fixtures := readPriorLefthookFixtures(t)
	for _, rendering := range strictGateRenderings {
		for _, name := range strictGateFixtureNames(rendering.fixture) {
			repoPath, rep := adoptMarkedRepo(t, rendering.fixture, rendering.markers, string(fixtures[name]))
			if got := mustRead(t, filepath.Join(repoPath, lefthookFile)); got != buildLefthookYAMLFor(lefthookShape{languages: adoptedLefthookLanguages(rendering.languages)}, false) {
				t.Errorf("%s: not migrated to the current rendering:\n%s", name, got)
			}
			if !hasAction(rep, lefthookFile, actionReconcile) || hasAction(rep, lefthookFile, actionReplace) {
				t.Errorf("%s: want a reconcile and no replace: %+v", name, rep.ActionDetails)
			}
			if !fileExists(filepath.Join(repoPath, ".git", "hooks", preCommitHook)) {
				t.Errorf("%s: the migrated configuration was not activated", name)
			}
		}
	}
}
