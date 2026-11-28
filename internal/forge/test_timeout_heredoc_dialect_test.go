package forge

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cordanaLLM/praetor/internal/util"
)

const timeoutSplitHeredoc = "cat <<EOF\nE\\\nOF\ngo test -timeout=45m ./...\nEOF\n"

// TestTimeoutAudit_HeredocDialect audits workflows with split or agreeing heredoc delimiters under sh and bash and checks each expected finding or pass.
func TestTimeoutAudit_HeredocDialect(t *testing.T) {
	for _, tc := range []struct {
		name, shell, script, want string
	}{
		{"sh split delimiter", "sh", timeoutSplitHeredoc, "unverifiable test invocation"},
		{"bash split delimiter", "bash", timeoutSplitHeredoc, "sets 45m, above the 30m bound"},
		{"sh agreeing continuation", "sh", "cat <<EOF\nno\\\nise\nEOF\ngo test -timeout=45m ./...\n", "sets 45m, above the 30m bound"},
		{"sh short command", "sh", "go test -timeout=5m ./...\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			yaml := "name: timeout\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: " + tc.shell + "\n        run: |\n"
			for _, line := range strings.Split(strings.TrimSuffix(tc.script, "\n"), "\n") {
				yaml += "          " + line + "\n"
			}
			writeWorkflowFixture(t, root, "timeout.yml", yaml)
			out, err := AuditTestTimeouts(context.Background(), TestTimeoutOptions{Root: root})
			assertHeredocAuditResult(t, out, err, tc.want)
		})
	}
}

// assertHeredocAuditResult requires PASS when want is empty; otherwise the error must contain want and must not mix bound and unverifiable finding classes.
func assertHeredocAuditResult(t *testing.T, out string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil || !strings.Contains(out, "[PASS] test-timeout") {
			t.Fatalf("audit = %q, %v; want PASS", out, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("audit = %q, %v; want %q", out, err, want)
	}
	if strings.Contains(err.Error(), "above the 30m bound") != strings.Contains(want, "above the 30m bound") ||
		strings.Contains(err.Error(), "unverifiable test invocation") != strings.Contains(want, "unverifiable test invocation") {
		t.Fatalf("audit mixed or misclassified findings: %v", err)
	}
}

// TestTimeoutAudit_HeredocShellOracle runs the split-delimiter fixture through local dash and bash to observe whether the go command executes, and skips when a shell is unavailable.
func TestTimeoutAudit_HeredocShellOracle(t *testing.T) {
	for _, tc := range []struct {
		name, shell string
		args        []string
		executesGo  bool
	}{
		{"dash", "dash", []string{"-s"}, false},
		{"bash", "bash", []string{"--noprofile", "--norc", "-s"}, true},
		{"bash-posix", "bash", []string{"--noprofile", "--norc", "--posix", "-s"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := exec.LookPath(tc.shell)
			if err != nil {
				t.Skipf("local shell unavailable: %v", err)
			}
			dir := t.TempDir()
			stdin := filepath.Join(dir, "stdin")
			// EOF is a command in the Bash interpretation; stub it as well as go.
			script := "go() { printf '%s\\n' EXECUTED_GO; }\nEOF() { :; }\n" + timeoutSplitHeredoc
			if err := os.WriteFile(stdin, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Redirect the fixture onto stdin so the oracle still runs with -s.
			args := []string{"-i", "PATH=/usr/bin:/bin", "LC_ALL=C", path, "-c",
				`exec env -i PATH=/usr/bin:/bin LC_ALL=C "$@" < "$0"`, stdin, path}
			out, err := util.RunCommand(ctx, dir, "env", append(args, tc.args...)...)
			if err != nil {
				t.Fatalf("shell: %v\n%s", err, out)
			}
			marker := strings.Contains(out+"\n", "EXECUTED_GO\n")
			body := strings.Contains(out+"\n", "go test -timeout=45m ./...\n")
			if marker != tc.executesGo || body == tc.executesGo {
				t.Fatalf("shell output = %q; want execution=%v and body=%v", out, tc.executesGo, !tc.executesGo)
			}
		})
	}
}
