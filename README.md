# UNASKED

> A research harness for blind, evidence-gated repository investigation.

[![CI](https://github.com/taipei49314/unasked/actions/workflows/ci.yml/badge.svg)](https://github.com/taipei49314/unasked/actions/workflows/ci.yml)
[![CodeQL](https://github.com/taipei49314/unasked/actions/workflows/codeql.yml/badge.svg)](https://github.com/taipei49314/unasked/actions/workflows/codeql.yml)

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

Python 3.11–3.14 and Git 2.45 or newer are required. The Git minimum makes object reads
fail closed instead of lazily fetching missing partial-clone objects from a remote.

### GitHub Release wheel

Download the wheel and checksum manifest from the public GitHub Release, verify the wheel
hash against `SHA256SUMS.txt`, then install it. The following PowerShell example fails if the
published checksum and downloaded wheel differ:

```powershell
$version = "0.3.0"
$wheel = "unasked_research-$version-py3-none-any.whl"
$release = "https://github.com/taipei49314/unasked/releases/download/v$version"
Invoke-WebRequest "$release/$wheel" -OutFile $wheel
Invoke-WebRequest "$release/SHA256SUMS.txt" -OutFile SHA256SUMS.txt
$expected = (Get-Content SHA256SUMS.txt | Where-Object { $_ -match [regex]::Escape($wheel) } | ForEach-Object { ($_ -split "\s+")[0] })
$actual = (Get-FileHash -Algorithm SHA256 $wheel).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "Release checksum mismatch" }
uv tool install ".\$wheel"
unasked --json resources export --destination .unasked-kit
unasked --json doctor
```

The exported kit contains the exact protocols, examples, custody guidance, constitution,
threat model, and templates bound to the installed build. Changed destination files are not
silently overwritten; repeat with `--force` only when replacement is intentional.

### Source checkout

```powershell
uv sync --locked --extra dev
uv tool install --editable .
unasked --json resources export --destination .unasked-kit
unasked --json doctor
```

The evidence core and scripted development provider are offline and do not use credentials.
The optional JSON-subprocess provider bridge launches one local argv-only executable with a
secret-stripped environment, a combined stdout/stderr cap, and the investigation's remaining
wall-time bound. UNASKED terminates its ordinary descendant process tree after success,
timeout, or output overflow (Windows Job Object; POSIX process group). Provider scripts or
model files can be named in `bound_files` so their hashes are frozen and rechecked around
execution. This lifecycle control is not a hostile-provider OS sandbox and does not prove
network isolation. Repository experiments use an executable allowlist, bounded
timeout, and fresh detached repositories. Formal evidence still requires an external
container/VM adapter that
records enforced network, secret, process, CPU, and disk isolation.

`observe` also seals a repository-wide knowledge scan. Experiment plans contain exact,
machine-evaluable assertions frozen before execution; an experiment reaches `SUPPORTED`
only when those assertions deterministically classify its raw hashes/exit codes as
`SUPPORTS`. The model cannot provide the reserved mutation command or invoke Git as an
experiment command; UNASKED performs one internal, no-follow filesystem capture covering
tracked, untracked, staged, and temporary Git-metadata mutations; root replacement and NTFS
alternate streams fail closed. Counterevidence requires four distinct CAS-backed challenge
results rather than prose alone.

## Command path

```powershell
unasked --json doctor
# Create a separate workspace/run for every opaque case and preregistered variant.
unasked --json init <repository> --commit <sha> --workspace <variant-workspace> `
  --protocol .unasked-kit/protocols/m0-development-v0.1.json `
  --model-provider scripted --model-name development-model `
  --trial-preregistration .unasked-kit/examples/trial-preregistration.json `
  --budget .unasked-kit/examples/m0-budget.json
unasked --json observe --workspace <variant-workspace> --run <run-id>
# For deterministic-detectors-only runs, execute only the baseline command:
unasked --json baselines run --workspace <variant-workspace> --run <run-id>
# For each of the other four variants, execute only investigate with its matching --mode:
unasked --json investigate --workspace <variant-workspace> --run <run-id> `
  --budget .unasked-kit/examples/m0-budget.json `
  --provider-config .unasked-kit/examples/provider-scripted.json `
  --mode <preregistered-mode>
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
unasked --json trials audit --report <aggregate-report.json> `
  --evidence-index <trial-evidence-index.json>
unasked --json trials certify --report <aggregate-report.json>
```

Use `unasked <command> --help` for required evidence fields. Commands never repair a target
repository. All target writes occur only in temporary worktrees.

Proposal, plan, challenge, and review JSON examples are in [`examples/`](examples/) and in
the exported resource kit. Actor IDs are recorded but not authenticated in the v0.1 evidence
protocol; organizational separation remains an external control. Trial preregistration and
evidence-index examples are templates: replace every placeholder commit and hash with values
computed for the actual sealed run. Preregistration and budget must be supplied together at
`init`; a legacy run cannot be retroactively converted into a trial run.

### Fail-closed replay

`replay run` proves that core command outputs match in a fresh Git worktree. It records
`network_isolated: false` because the local adapter cannot enforce an OS security boundary.
The authority kernel therefore refuses `VERIFIED` even when local replay passes. A genuine
isolated reproducer must first import all CAS artifacts with `artifacts add`, then use
`replay import` with independently produced replay and environment manifests.
The imported environment must bind the target, frozen plan, executable set, independent
command-result records, and a CAS-backed isolation receipt whose structured subject must bind
the replay inputs and outputs. Because v0.3.0 has no independently configured signature trust
root, the authority kernel deliberately treats every imported receipt as unauthenticated:
the evidence may be retained and reach `REPRODUCED`, but it cannot authorize `VERIFIED`.

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
5-positive/2-control results cannot authorize an M0 claim.

The three trial commands have deliberately different authority:

- `trials evaluate` deterministically recomputes aggregate metrics from a manifest and the five
  result arms. It trusts the result documents only as metric inputs.
- `trials audit` dereferences a separately hashed evidence index into each preregistered run,
  ledger head, CAS or run result, and the complete current `VERIFIED` certificate set. It returns
  a readable `PASS` or `FAIL` structural matrix, but all authorization checks remain false and
  the output is always `NON_CERTIFYING` with `m0_demonstrated=false`. Workspaces must be safe
  relative paths resolved beneath the evidence-index directory.
- `trials certify` still recomputes and then denies. Version 0.3 has no authenticated actor or
  custody identities, external attestation trust root, or external ledger checkpoint, so a
  structural audit can never unlock certification.

Input booleans are metrics, not authority. UNASKED never
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

Each workspace contains immutable run metadata, a hash-chained event ledger whose
verify-plus-append transaction is serialized across local threads and processes, append-only
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
uv sync --locked --extra dev --extra security
uv run ruff check .
uv run ruff format --check .
uv run bandit -q -r src scripts
uv export --locked --no-dev --no-emit-project --format requirements.txt --output-file .runtime-requirements.txt
uv run pip-audit -r .runtime-requirements.txt --progress-spinner off
uv run pytest
python scripts/verify_release.py
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution policy,
[`SECURITY.md`](SECURITY.md) for confidential vulnerability reporting, and
[`RELEASING.md`](RELEASING.md) for the tag-bound, reproducible GitHub Release process.

## License and public status

This repository is publicly readable but is not currently offered under an open-source
license. Copyright is reserved and no permission to copy, modify, redistribute, or create
derivative works is granted except where applicable law allows it. See [`LICENSE`](LICENSE).
Public visibility is not an M0 claim and does not change the non-certifying boundary above.
