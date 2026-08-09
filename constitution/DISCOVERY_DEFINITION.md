# Discovery definition

A result may be labeled `VERIFIED` only when every gate below has machine-verifiable
evidence and an authorized actor distinct from the proposer approves the verdict.

| Gate | Required evidence |
|---|---|
| Unasked | Frozen prompt/context manifest and blindness attestation show no directional hint. |
| Previously unstated | A completed scan over the predeclared knowledge boundary. |
| Discrepancy | A sourced expectation and a directly observed contradiction. |
| Material | Predeclared decision class and an approved materiality review. |
| Falsifiable | A condition that would reject the main hypothesis. |
| Evidence-backed | Raw command/output/artifact references with verified hashes. |
| Reproducible | Successful replay from a fresh worktree at the bound commit. |
| Counterevidence-surviving | A reasonable benign alternative, negative control, and completeness check were attempted. |
| Externally authorized | `AUTHORIZE_VERDICT` capability held by an actor other than the proposer. |

Textual declarations alone do not complete these gates. The P0 verifier requires a sealed
knowledge-scan manifest, deterministic experiment assertions classified as `SUPPORTS`, four
distinct structured challenge results, independent replay command records, and a bound
external-isolation receipt. Receipt issuer identity remains an explicitly external control.

## Lifecycle

`SIGNAL → CANDIDATE → HYPOTHESIZED → TESTABLE → SUPPORTED → REPRODUCED → VERIFIED`

At an applicable non-final state a candidate may instead become `FALSIFIED`, `DUPLICATE`,
`INCONCLUSIVE`, `NON_MATERIAL`, `ENVIRONMENTAL`, or `STALE`. A previously verified claim
may become `REVOKED` or `STALE`. Transitions are append-only events; records are never
rewritten to hide a prior conclusion.

## Explicit non-discoveries

Ideas, static warnings without demonstrated consequence, existing failing tests, style
findings, environment-only failures, known issues, prompted findings, model confidence,
non-replayable observations, and unsupported global-novelty claims cannot be `VERIFIED`.
