# Private benchmark custody protocol

The private benchmark is intentionally **not** stored in this repository. A custodian who
does not implement or operate the Explorer must create a separate access-controlled store
before an M0 blind run.

For each sealed case the custodian records: immutable target commit, hidden discrepancy,
materiality class, minimum evidence, disallowed shortcuts, false-positive traps, valid
counterevidence, clean replay procedure, knowledge boundary, sealing time, and manifest
SHA-256. Five positive cases and two clean/decoy controls are required for formal M0.

Before any trial run, the custodian assigns opaque suite and case identifiers. The public
trial preregistration contains only those identifiers, the ablation variant, frozen target,
protocol, budget and model bindings, and their hashes. It must not disclose the case kind,
ground truth, expected result, minimum evidence, materiality, traps, or replay procedure.
Those fields remain solely in the access-controlled manifest. The same opaque identifier is
used across the five preregistered variants without giving the Explorer a semantic label.

The Explorer receives only the target snapshot and frozen high-level prompt. The evaluator
receives Explorer outputs only after run lock. Access logs and the sealed manifest hash are
attached by the custodian, never synthesized by the Explorer.

This project can validate a custodian-provided public manifest hash, but cannot attest that
data was private or that organizational access controls existed. Those remain external
evidence.
