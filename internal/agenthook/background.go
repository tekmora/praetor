// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package agenthook

// backgroundOperator matches a bare & in shell code, including before a closing
// subshell or group. Neighbours exclude &&, &>, >&, <&, |& and case fall-through
// operators ;& and ;;&. Fixed-width neighbours keep RE2 matching linear.
const backgroundOperator = `(?:^|[^&<>|;])&(?:[^&>]|$)`

// backgroundRule reuses the admission reader's shell lexer through denyRule.matches:
// quoted data, escaped bytes, comments and here-document bodies cannot match.
// Unreadable shell input fails closed while this opt-in rule is active.
func backgroundRule() denyRule {
	rule := builtinRule(BuiltinRule{Source: backgroundOperator, Invariant: "HISS"},
		"bare-background rule (hooks.background.enforce): bare & prohibited or command unreadable; "+
			"use client's background-task mechanism or systemd user unit")
	rule.shellCodeOnly = true
	return rule
}
