// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"strings"
	"testing"
)

func TestAuditTestTimeouts_MakeGOFLAGSGraph(t *testing.T) {
	const export = "release: export GOFLAGS := -timeout=0\n"
	const check = "check: ; go test -timeout=30m ./...\n"
	const inherited = "cannot verify inherited GOFLAGS from Make exports"
	for _, tc := range []struct{ name, makefile, want string }{
		{"independent", export + "release: ; @true\n" + check, ""},
		{"independent long timeout", export + "check: ; go test -timeout=45m ./...\n", ":2 sets 45m, above the 30m bound"},
		{"direct tab recipe", export + "release:\n\tgo test ./...\n", ":3 unverifiable test invocation: " + inherited},
		{"transitive order-only", export + "release:: setup\nsetup: | check\n" + check, ":4 unverifiable test invocation: " + inherited},
		{"multi-target repeated rule", "release publish: override export GOFLAGS = -timeout=0\npublish: ; @true\npublish: ./check\n" + check, ":4 unverifiable test invocation: " + inherited},
		{"no reverse inheritance", export + "check: release ; go test -timeout=30m ./...\nrelease: ; @true\n", ""},
		{"private direct", "check: private export GOFLAGS := -timeout=0\n" + check, ":2 unverifiable test invocation: " + inherited},
		{"private prerequisite", "release: export private GOFLAGS := -timeout=0\nrelease: check\n" + check, ""},
		{"phony is not an edge", "release: export GOFLAGS := -timeout=0\n.PHONY: release check\nrelease: ; @true\n" + check, ""},
		{"global named export", "export GOFLAGS\nGOFLAGS = -timeout=0\n" + check, ":3 unverifiable test invocation: " + inherited},
		{"global blanket export", ".EXPORT_ALL_VARIABLES:\nGOFLAGS = -timeout=0\n" + check, ":3 unverifiable test invocation: " + inherited},
		{"read-time command has no target environment", export + "RESULT != go test -timeout=30m ./...\n", ""},
		{"unresolved dependency", export + "release: $(DEPS)\n" + check, ":3 unverifiable test invocation: cannot resolve target graph for inherited GOFLAGS: Makefile:2: unsupported prerequisite $(DEPS)"},
		{"bounded fanout", export + strings.Repeat("release ", 300) + ": " + strings.Repeat("check ", 300) + "\n" + check, ":3 unverifiable test invocation: cannot resolve target graph for inherited GOFLAGS: Makefile:2: target graph exceeds the 65536-entry bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTimeoutFile(t, "Makefile", tc.makefile, tc.want)
		})
	}
}
