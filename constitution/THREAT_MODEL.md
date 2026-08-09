# Threat model

The repository-grounded P0 threat model is maintained at
[`../unasked-threat-model.md`](../unasked-threat-model.md).

Its binding implementation decisions are:

1. `local_restricted` execution is not a security sandbox and cannot by itself satisfy the
   clean-replay authorization gate.
2. Actor IDs and external custody/replay attestations are unauthenticated in v0.1; public M0
   claims therefore require independent organizational verification.
3. Ledger and CAS hashes detect mutation but do not prevent deletion or whole-workspace
   rollback; externally signed checkpoints are required before adversarial deployment.
4. No private benchmark, model provider, network service, or automatic repair is part of P0.

Changing these decisions requires a new protocol version and applies only to future runs.
