# Pull Request

## Description

<!-- markdownlint-capture -->
<!-- markdownlint-disable MD013 -->
<!-- Provide a concise description of what this PR introduces, refactors, or fixes. -->
<!-- markdownlint-restore -->

## Pre-Merge Verification Checklist

- [ ] Local verification passed: `make verify-all`
- [ ] No new HISS / NASA Power-of-10 infractions
- [ ] 3D Tests included (Positive, Negative, Boundary) for public APIs
- [ ] Agent contexts in sync: `standardsctl compile-context --verify`
- [ ] Commit messages adhere to Conventional Commits format

### 1. High-Integrity Systems Standard (HISS) Checklist

All PRs must strictly adhere to the declared HISS invariants before merging:

#### Static & Runtime Determinism

- [ ] **HISS-01** The call graph is acyclic, including indirect calls.
- [ ] **HISS-02** Every loop has a compile-time scalar upper bound.
- [ ] **HISS-02** All network and disk I/O uses explicit context timeouts.
- [ ] **HISS-03** Hot-path loops allocate zero heap bytes per tick.
- [ ] **HISS-04** Meet the effective per-function limits from `.standards.yaml`.
  - Function LOC <= 60 and statements <= 50.
  - McCabe cyclomatic <= 10 and cognitive <= 15.

#### Memory & Error Integrity

- [ ] **HISS-07** Handle or wrap every error. No `.unwrap()` or `.expect()`.
- [ ] **HISS-08** No dynamic evaluation or banned C calls (e.g. `strcpy`).
- [ ] **HISS-09** Each unsafe operation has a preceding `// SAFETY:` proof.
- [ ] **HISS-10** The compiler and all configured linters report zero warnings.

#### Supply Chain & API Governance

- [ ] **HISS-11** Pin dependencies, lockfiles, and container images.
- [ ] **HISS-14** Mark breaking API changes with `!` and a `Migration:` footer.

---

### 2. Three-Dimensional (3D) Testing Verification (HISS-15)

Cover every public method and changed component with automated tests.

- [ ] **HISS-15 positive tests** Check outputs for normal and golden inputs.
- [ ] **HISS-15 negative tests** Check errors for invalid or denied inputs.
- [ ] **HISS-15 boundary tests** Cover zero, one, empty inputs, and maxima.
- [ ] **HISS-13** Scan every supported file and keep total debt from rising.

---

### 3. Context Integrity & Agent Governance (HISS-16)

- [ ] Edit agent rules in the canonical `AGENTS.md`.
- [ ] `standardsctl compile-context --verify` reports zero diffs.
- [ ] Generate all client rule files from the canonical instructions.
- [ ] Leave hooks enabled and `.git/hooks` intact.

---

### 4. Ed25519 Exit-0 Verification Receipt

If the gate signs a receipt for this head, paste its JSON in the fence below.

Otherwise, record which verification ran and the reason the gate reported.

`praetorctl gate run` writes signed receipts to `.standards-receipt.json`.

If pre-push kept a copy, find it at `.git/praetor-receipts/<sha>.json`.

Run the gate again after a rebase.

```receipt
```

- [ ] Record the test command you ran and its outcome.
