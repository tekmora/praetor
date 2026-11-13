// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package agenthook

import (
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/config"
)

func TestBackground_Negative_BareOperators(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		policy, err := BuildPolicy(config.HookSettings{Background: config.BackgroundSettings{Enforce: enforce}})
		if err != nil {
			t.Fatal(err)
		}
		for name, command := range map[string]string{
			"trailing": "sleep 5 &", "build": "make build &",
			"subshell": "(launch.sh > log 2>&1 &)", "group": "{ job & }", "list": "a & b",
			"adjacent": "job&", "newline": "echo ok\njob &\necho next",
			"substitution": `echo "$(job &)"`, "backtick": "echo `job &`",
			"after heredoc": "cat <<EOF\nquoted & data\nEOF\njob &",
		} {
			t.Run(name+"/enforce="+map[bool]string{true: "true", false: "false"}[enforce], func(t *testing.T) {
				got := policy.Command(command)
				if enforce {
					requireDeniedContaining(t, command, got, "bare-background", "hooks.background.enforce",
						"client's background-task mechanism", "systemd user unit")
				} else if got.Outcome != Allow {
					t.Fatalf("unset enforcement %q: %+v", command, got)
				}
			})
		}
	}
}

func TestBackground_Positive_DataAndOtherOperators(t *testing.T) {
	policy, err := BuildPolicy(config.HookSettings{Background: config.BackgroundSettings{Enforce: true}})
	if err != nil {
		t.Fatal(err)
	}
	for name, command := range map[string]string{
		"and": "a && b", "duplicate fd": "cmd > f 2>&1", "duplicate output": "cmd >& f",
		"redirect": "cmd &> f", "append": "cmd &>> f", "pipe": "cmd |& tee f",
		"double quotes": `echo "a & b"`, "single quotes": `echo 'x&y'`,
		"url": `curl "https://h/p?a=1&b=2"`, "escape": `echo x\&y`, "comment": "echo ok # job &",
		"heredoc": "cat <<EOF\njob &\nEOF", "quoted heredoc": "cat <<'EOF'\njob &\nEOF",
		"tab heredoc": "cat <<-EOF\n\tjob &\n\tEOF", "input fd": "cmd <&0",
		"case":  "case x in x) echo ok ;& y) echo next ;;& z) echo end ;; esac",
		"empty": "", "crlf": "echo ok\r\necho '&'\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := policy.Command(command); got.Outcome != Allow {
				t.Fatalf("%q: %+v", command, got)
			}
		})
	}
}

func TestBackground_Boundary_UnreadableAndLineLimit(t *testing.T) {
	policy, err := BuildPolicy(config.HookSettings{Background: config.BackgroundSettings{Enforce: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`echo "open`, "cat <<EOF\nbody", strings.Repeat("\n", admissionMaxLines)} {
		requireDeniedContaining(t, command, policy.Command(command), "bare-background", "command unreadable")
	}
	if got := policy.Command(strings.Repeat("\n", admissionMaxLines-1)); got.Outcome != Allow {
		t.Fatalf("exact line limit: %+v", got)
	}
}
