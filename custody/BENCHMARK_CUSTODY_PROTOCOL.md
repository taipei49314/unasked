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

For v0.4, custody, isolation, ledger-witness, discovery-authority, evaluator, and certifier
keys are provisioned outside UNASKED. The trust policy is read once as exact bytes and pinned
by a caller-provided lowercase SHA-256 before parsing. Private keys must remain in independent
signing systems; they are never placed in the repository, exported resource kit, run
workspace, or provider environment. Production role thresholds use unique keys and unique
actor identities. A custodian actor must not also be the Explorer, executor, evaluator,
authority, isolation attester, ledger witness, or M0 certifier.

Each of the 35 runs needs an external isolation statement over the exact result bytes and a
final ledger checkpoint over the exact complete ledger bytes. If a discovery was authorized,
the final checkpoint comes after the unique `AUTHORIZATION_COMMITTED` event and binds the
complete marker set. The authority signs the deterministic prepared pre-state graph; commit
re-verifies all exact inputs while holding the run mutation lock. Any drift, missing marker,
rollback, duplicate event, or substituted envelope invalidates the bundle.

The evaluator signs only after all run outputs are locked, and the M0 certifier signs the
evaluation envelope only after independently checking custody, the full 5-by-7 matrix,
positive/control thresholds, replay, and provenance. A SHADOW policy is useful for dry runs
but is categorically unable to authorize `M0_DEMONSTRATED`.

Cryptographic verification proves that configured keys signed exact bytes. It cannot prove
that people or organizations were genuinely independent, that a host or signing device was
uncompromised, that no out-of-band ground-truth leakage occurred, or that a claimed isolation
platform enforced its controls. Those facts require real-world governance, access logs,
platform assurance, and independent audit beyond this software.
