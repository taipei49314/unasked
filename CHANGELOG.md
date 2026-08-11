# Changelog

All notable software changes are recorded here. Milestone claims remain governed by
`constitution/CLAIMS_POLICY.md` and require independent evidence beyond a software release.

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
