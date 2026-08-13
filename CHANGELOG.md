# Changelog

All notable software changes are recorded here. Milestone claims remain governed by
`constitution/CLAIMS_POLICY.md` and require independent evidence beyond a software release.

## 0.4.0 — 2026-08-13

### Added

- Exact-byte SHA-256-pinned external trust policies, Ed25519 verification, DSSE PAE, and
  in-toto Statement v1 predicates for custody, isolation, ledger checkpoints, discovery
  authorization, trial evaluation, and M0 certification.
- A two-phase authority flow that prepares a deterministic pre-state graph and commits under
  the run mutation lock only after re-verifying signed authority and checkpoint envelopes.
- Authenticated v0.4 M0 verification across the complete 5-by-7 run matrix, exact result and
  ledger bytes, every authorization marker, final checkpoints, evaluator statement, and
  certifier statement.

### Security

- Enforce trust-role thresholds by unique keys and, in PRODUCTION, unique actors; reject
  revoked, premature, expired, cross-role, or substituted signing identities.
- Bind external envelope bytes, CAS graphs, pre-commit and final ledger heads, marker events,
  trial index entries, and all relative locators without following links outside their roots.
- Keep legacy authorization and reporting fail closed; externally authenticated v0.4 evidence
  is required before a `VERIFIED` certificate can be treated as authoritative.

### Claim boundary

This software release includes authenticated verification machinery, not authenticated
research results. Its public trust-policy example is `SHADOW`, contains no private key, and
can never authorize `M0_DEMONSTRATED`. No independently held sealed benchmark was run for
this release; the repository's public status remains `m0_demonstrated=false`, and the exact
result without complete independent production evidence is `M0_NOT_DEMONSTRATED`.

## 0.3.0 — 2026-08-13

### Added

- Immutable pre-execution trial preregistration bound to target commit, protocol, finite
  budget, model identity, suite/case identifier, and ablation variant.
- A self-hashed trial evidence index and deterministic structural audit that
  dereferences run identity, ledger heads, baseline/investigation results, and the complete
  current `VERIFIED` certificate set.
- `trials audit --report --evidence-index` with readable PASS/FAIL matrices, fixed
  authorization blockers, and stable JSON/exit-code behavior.

### Security

- Reject tampered trial bindings before the first provider call and reject mismatched
  baseline/investigation variants before execution.
- Constrain evidence workspaces beneath the index directory, distinguish canonical JSON
  hashes from file-byte hashes, and re-run the existing certificate authority audit instead
  of trusting index claims.
- Harden the public report and audit schemas so they cannot validate an M0 success claim or
  a structural PASS whose required checks are false.

### Claim boundary

Structural audit is evidence completeness checking, not authorization. Every audit keeps
actor/custody authentication and external trust-root/checkpoint verification false; every
output remains `NON_CERTIFYING` with `m0_demonstrated=false`, and `trials certify` still
fails closed.

## 0.2.2 — 2026-08-13

### Security

- Terminate the JSON-subprocess provider's ordinary descendant process tree on timeout,
  combined-output overflow, and normal parent exit by using a Windows Job Object or POSIX
  process group.
- Serialize the ledger's full-chain scan and durable append with a per-ledger thread and OS
  file lock, preventing duplicate sequences and parent hashes under concurrent writers.
- Parse and bind external isolation receipt subjects to replay inputs and outputs, but keep
  every imported receipt unauthenticated and ineligible for `VERIFIED` until an external
  signature trust root is implemented.

### Claim boundary

This release remains `NON_CERTIFYING` with `m0_demonstrated=false`. An imported replay may be
recorded as `REPRODUCED`, but no external receipt can satisfy the authorization gate in this
version.

## 0.2.1 — 2026-08-11

### Added

- Public security, support, conduct, contribution, issue, and pull-request policies with an
  explicit source-visible, reserved-rights license boundary.
- CodeQL, Dependabot, Bandit, and locked runtime dependency auditing in CI.

### Security

- Replace runtime assertions at artifact, repository, and capture integrity boundaries with
  explicit fail-closed errors that remain active under optimized Python execution.
- Pin current Node 24 GitHub Actions by immutable commit and keep workflow credentials out of
  checked-out Git configuration.

### Claim boundary

This release remains `NON_CERTIFYING` with `m0_demonstrated=false`. Public repository
visibility does not demonstrate M0 and does not make model output evidence.

## 0.2.0 — 2026-08-11

### Added

- P0 schemas, immutable snapshots, observations, CAS artifacts, append-only ledger, lifecycle
  policy, replay, reviews, deterministic authority gates, and verified-only reporting.
- An unsealed bounded Explorer, deterministic baselines, five ablation modes, trial metrics,
  and strict non-certifying M0 development outputs.
- Package resource export for protocols, examples, custody guidance, governance documents,
  and work-package templates.
- Cross-platform CI, repeat-build comparison, distribution integrity checks, wheel smoke
  tests, and tag-driven GitHub Releases.

### Security

- Freeze trusted Git before touching a target and reject current-directory, repository,
  namespace-alias, config-base, script, and linked PATH shadows.
- Require Git 2.45+, disable lazy fetching by command-line and environment controls, and
  disable interactive credential access during immutable reads.
- Replace source-configured reads and clean checks with isolated metadata views that never
  parse target config/includes, hooks, or filter commands; reject linked/alternate object
  databases and repack temporary checkouts before exposing them.
- Reserve mutation capture to an internal authority-controlled filesystem manifest;
  model-authored Git commands are rejected, root replacement and NTFS ADS fail closed, and
  cleanup does not follow repository-created links.
- Bind external replay input to the exact original experiment capability manifest.

### Claim boundary

This release remains `NON_CERTIFYING` with `m0_demonstrated=false`. It does not contain an
independently sealed benchmark, does not prove OS isolation, and does not demonstrate M0.
