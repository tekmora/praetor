// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import "testing"

// TestAuditTestTimeouts_MakeTargetSpecificGOFLAGS distinguishes exported bindings from lookalike syntax.
func TestAuditTestTimeouts_MakeTargetSpecificGOFLAGS(t *testing.T) {
	assertTimeoutFile(t, "Makefile", "test: export GOFLAGS := -timeout=0\ntest: ; go test ./...\n",
		":2 unverifiable test invocation: cannot verify inherited GOFLAGS from Make exports")
	assertTimeoutFile(t, "Makefile", "test: GOFLAGS := -timeout=0\ntest: ; go test ./...\n", "")
	assertTimeoutFile(t, "Makefile", "test: export OTHER := GOFLAGS\ntest: ; go test ./...\n", "")
	assertTimeoutFile(t, "Makefile", "test: export GOFLAGS\nexport: ; go test -timeout=30m ./...\n", "")
}

// TestAuditTestTimeouts_MakeShellAssignment checks which assignment text executes at read time.
func TestAuditTestTimeouts_MakeShellAssignment(t *testing.T) {
	assertTimeoutFile(t, "Makefile", "RESULT != go test -timeout=45m ./...\n", ":1 sets 45m, above the 30m bound")
	assertTimeoutFile(t, "Makefile", "# heading\nRESULT != \\\n  go test -timeout=45m ./...\n", ":3 sets 45m, above the 30m bound")
	assertTimeoutFile(t, "Makefile", "RESULT != go test -timeout=30m ./...\n", "")
	assertTimeoutFile(t, "Makefile", "RESULT != printf '%s\\n' ok # go test -timeout=45m ./...\n", "")
	assertTimeoutFile(t, "Makefile", "RESULT := go test -timeout=45m ./...\nDEFERRED = $(shell go test -timeout=45m ./...)\nOPTIONAL ?= $(shell go test -timeout=45m ./...)\ntest: ; go test -timeout=30m ./...\n", "")
}
