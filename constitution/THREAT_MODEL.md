# Threat model

The repository-grounded P0 threat model is maintained at
[`../unasked-threat-model.md`](../unasked-threat-model.md).

Its binding implementation decisions are:

1. `local_restricted` execution is not a security sandbox and cannot by itself satisfy the
   clean-replay authorization gate.
2. Legacy actor IDs and custody/replay declarations remain unauthenticated. The v0.4 trust
   plane verifies externally provided Ed25519 DSSE/in-toto statements against an exact-byte
   policy pin, but public claims still require independently operated PRODUCTION keys and
   organizational verification of separation, custody, and platform facts.
3. Ledger and CAS hashes detect mutation but do not prevent deletion or whole-workspace
   rollback. V0.4 can authenticate externally signed checkpoints; operators must retain and
   compare those checkpoints outside the mutable workspace.
4. No private benchmark, production trust root, model provider, network service, or automatic
   repair is included in the public distribution.

Changing these decisions requires a new protocol version and applies only to future runs.
