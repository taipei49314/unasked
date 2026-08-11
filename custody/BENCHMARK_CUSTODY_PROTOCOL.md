# Private benchmark custody protocol

The private benchmark is intentionally **not** stored in this repository. A custodian who
does not implement or operate the Explorer must create a separate access-controlled store
before an M0 blind run.

For each sealed case the custodian records: immutable target commit, hidden discrepancy,
materiality class, minimum evidence, disallowed shortcuts, false-positive traps, valid
counterevidence, clean replay procedure, knowledge boundary, sealing time, and manifest
SHA-256. Five positive cases and two clean/decoy controls are required for formal M0.

The Explorer receives only the target snapshot and frozen high-level prompt. The evaluator
receives Explorer outputs only after run lock. Access logs and the sealed manifest hash are
attached by the custodian, never synthesized by the Explorer.

This project can validate a custodian-provided public manifest hash, but cannot attest that
data was private or that organizational access controls existed. Those remain external
evidence.
