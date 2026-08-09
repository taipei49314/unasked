# UNASKED

> A research harness for blind, evidence-gated repository investigation.

UNASKED records repository observations, falsifiable hypotheses, restricted experiments,
counterevidence, clean replay, and independent verdict authorization. Its central rule is
that model output is never evidence and a proposer can never promote its own result to
`VERIFIED`.

This repository includes the P0 authority foundation and an **unsealed M0 development
execution path**: a bounded single-provider Explorer, deterministic baselines, the five
required ablation arms, and aggregate trial metrics. It does **not** claim to find unknown
bugs or to have passed an independently sealed M0 evaluation. `NO_VERIFIED_DISCOVERY` is a
valid and expected result.

## Install

Python 3.11+ and Git are required.

```powershell
uv sync --extra dev
uv tool install --editable .
unasked --json doctor
```

The evidence core and scripted development provider are offline and do not use credentials.
The optional JSON-subprocess provider bridge launches one local argv-only executable with a
secret-stripped environment, a combined stdout/stderr cap, and the investigation's remaining
wall-time bound. Provider scripts or model files can be named in `bound_files` so their hashes
are frozen and rechecked around execution. UNASKED does not prove that the provider process
itself is network-isolated. Repository experiments use an executable allowlist, bounded
timeout, and fresh detached repositories. Formal evidence still requires an external
container/VM adapter that
records enforced network, secret, process, CPU, and disk isolation.

`observe` also seals a repository-wide knowledge scan. Experiment plans contain exact,
machine-evaluable assertions frozen before execution; an experiment reaches `SUPPORTED`
only when those assertions deterministically classify its raw hashes/exit codes as
`SUPPORTS`. Counterevidence requires four distinct CAS-backed challenge results rather than
prose alone.

## Command path

```powershell
unasked --json doctor
unasked --json init <repository> --commit <sha> --workspace <path> `
  --protocol protocols/m0-development-v0.1.json `
  --model-provider scripted --model-name development-model
unasked --json observe --workspace <path> --run <run-id>
unasked --json baselines run --workspace <path> --run <run-id>
unasked --json investigate --workspace <path> --run <run-id> `
  --budget examples/m0-budget.json --provider-config examples/provider-scripted.json
unasked --json expectations add ...
unasked --json candidates propose ...
unasked --json experiments plan ...
unasked --json experiments execute ...
unasked --json candidates transition ... --to SUPPORTED
unasked --json challenge ...
unasked --json replay run ...
unasked --json reviews novelty ...
unasked --json reviews known-issue ...
unasked --json reviews materiality ...
unasked --json attest custody ...
unasked --json verify ... --check-only
unasked --json report --workspace <path> --verified-only
unasked --json trials evaluate --manifest <private-manifest.json> --results <results.json>
unasked --json trials certify --report <aggregate-report.json>
```

Use `unasked <command> --help` for required evidence fields. Commands never repair a target
repository. All target writes occur only in temporary worktrees.

Proposal, plan, challenge, and review JSON examples are in [`examples/`](examples/). Actor
IDs are recorded but not authenticated in v0.1; organizational separation remains an
external control.

### Fail-closed replay

`replay run` proves that core command outputs match in a fresh Git worktree. It records
`network_isolated: false` because the local adapter cannot enforce an OS security boundary.
The authority kernel therefore refuses `VERIFIED` even when local replay passes. A genuine
isolated reproducer must first import all CAS artifacts with `artifacts add`, then use
`replay import` with independently produced replay and environment manifests.
The imported environment must bind the target, frozen plan, executable set, independent
command-result records, and a CAS-backed isolation receipt. The receipt issuer remains an
external trust assumption in v0.1; it is not a cryptographic platform attestation.

`report --verified-only` does not trust a certificate merely because the file exists. It
re-runs the frozen gate registry and verifies the verdict, complete CAS reference closure,
run/candidate identities, snapshot/protocol bindings, state history, and adjacent issuance
events before returning any certificate.

### M0 development execution

`investigate` accepts exactly one frozen provider identity and one finite budget. Each turn
contains one strict JSON action. Snapshot reads come from immutable Git objects; every model
request, raw response, tool result, candidate provenance record, and budget decision is
stored in CAS and linked from the ledger. The model may read/search, add a sourced
expectation, propose a candidate/hypothesis, and request a frozen experiment plan. It cannot
challenge, replay, review, verify, publish, or write a verdict/certificate. `--execute-plans`
is an explicit execution authorization and still obeys `--allow` executable limits.

The four model modes are `read_only_llm`, `llm_tools_no_experiment_gate`,
`experiment_loop_no_falsifier`, and `full_evidence_gated`; deterministic-only comparison is
provided by `baselines run`. Trial aggregation compares the charter's five preregistered
arms using exact decimal metrics and TUDY accounting.

The supplied development provider and examples deliberately skipped independent benchmark
custody. Consequently every `investigate` result is labeled `UNSEALED_DEVELOPMENT`, with
`certification.status = NON_CERTIFYING` and `m0_demonstrated = false`. Even perfect unsealed
5-positive/2-control results cannot authorize an M0 claim. Version 0.2 also keeps a structurally
"sealed" input non-certifying: `trials certify` always rejects until an external verifier can
authenticate custody and dereference every finding into its certificate, CAS, ledger, run,
replay, and protocol bundle. Input booleans are metrics, not authority. UNASKED never
synthesizes a custody attestation. A future formal M0 run still needs evidence sealed by an
independent custodian before Explorer development, 3/5 positive cases, zero false `VERIFIED`
controls, complete context provenance, and 100% clean replay.

## JSON contract

With `--json`, stdout contains exactly one JSON object.

Success:

```json
{"ok": true, "command": "doctor", "data": {}}
```

Failure:

```json
{
  "ok": false,
  "command": "verify",
  "error": {"code": "POLICY_DENIED", "message": "...", "details": {}}
}
```

Diagnostics go to stderr. No auth tokens are accepted or printed.

## Evidence layout

Each workspace contains immutable run metadata, a hash-chained event ledger, append-only
observation/expectation records, content-addressed artifacts, and candidate bundles matching
the layout in the North Star charter. SQLite is a rebuildable lookup index only; JSON,
JSONL, raw outputs, and their hashes remain the source of truth.

Constitutional policy lives in [`constitution/`](constitution/), including an exact-byte
copy of the supplied v0.1 charter bound to its documented SHA-256. The private benchmark is
not part of this repository; see
[`custody/BENCHMARK_CUSTODY_PROTOCOL.md`](custody/BENCHMARK_CUSTODY_PROTOCOL.md).
The repository-grounded security analysis is in
[`unasked-threat-model.md`](unasked-threat-model.md).

## Development

```powershell
uv run ruff check .
uv run pytest
```
