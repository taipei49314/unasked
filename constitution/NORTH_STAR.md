# UNASKED North Star — frozen P0 extract

> **Allowed P0 claim:** A research harness for blind, evidence-gated repository investigation.

This file is the implementation-facing constitutional extract of
`UNASKED_NORTH_STAR_v0.1.md`. The supplied source charter is bound by SHA-256:

`3c5b6e607f460581c7a85ecdbb695a54681a8d34b5bc2418896c3ab9dd0b86a`

Changing this document or any policy derived from it creates a new protocol version. A
running investigation remains bound to the earlier bytes and hash.

## North star

Build a system that independently identifies a previously unstated,
decision-relevant discrepancy; forms a falsifiable hypothesis; designs and executes an
experiment; survives an active attempt to disprove itself; and earns the right to report
the result through independently reproducible evidence.

The first bounded world is **software repository truth discovery**. The only permitted
high-level investigation prompt is:

> Investigate this repository for material discrepancies. Do not assume that a discovery exists.

The Explorer must not receive a problem class, target file, failing test, error message,
known vulnerability location, hidden ground truth, evaluator, or directional hint.

## Constitutional rules

1. **C-01 Evidence before interpretation.** Model prose is not raw evidence.
2. **C-02 Separation of proposal and authority.** A proposer cannot authorize its result.
3. **C-03 Snapshot binding.** Claims bind commit, data, policy, and tool versions.
4. **C-04 Context provenance.** Record every prompt, visible file, tool result, and boundary.
5. **C-05 Clean replay.** `VERIFIED` requires replay without prior hidden state.
6. **C-06 Counterevidence required.** At least one reasonable alternative must be tested.
7. **C-07 Silence is valid.** `NO_VERIFIED_DISCOVERY` is a successful, valid result.
8. **C-08 Hidden evaluation is sealed.** Explorer cannot read ground truth or evaluators.
9. **C-09 No retroactive criteria.** Policy changes never alter an existing run.
10. **C-10 Append-only history.** Failures and corrections remain in the ledger.
11. **C-11 Known is not discovered.** Known findings are `DUPLICATE` or `REDISCOVERED`.
12. **C-12 Confidence is not authority.** Model confidence grants no capability.

## Scope locks

- No dashboard before M2.
- No model swarm before a single-model baseline exists.
- No continuous proactive notification before M3.
- No automatic repair before M4.
- No Greenwash or ClaimGate code integration before M1.
- No vector database, long-term memory, or complex knowledge graph without measured need.
- No general autonomous-discovery claim before M5.
- No claim that the system has learned proactive discovery before a sealed benchmark passes.

This repository therefore implements a P0 harness and early M0 execution primitives. It
does not contain a private benchmark, does not self-authorize M0, and does not claim that
discovery capability has been demonstrated.
