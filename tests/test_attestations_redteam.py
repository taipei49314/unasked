from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unasked.attestations import (
    verify_custody_attestation,
    verify_isolation_attestation,
    verify_ledger_checkpoint,
    verify_m0_certification,
    verify_trial_evaluation,
)
from unasked.errors import IntegrityError
from unasked.ledger import EventLedger
from unasked.schemas import SchemaValidationError
from unasked.trust import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    PREDICATE_ROLES,
    TrustPolicy,
    VerifiedStatement,
    dsse_pae,
)
from unasked.util import canonical_json, sha256_bytes

_NOW = "2026-01-10T00:00:00Z"
_HASH = "a" * 64
_SUITE = "suite-redteam"
_CASE = "case-1"
_RUN = "run-redteam"
_SNAPSHOT = "b" * 64
_PROTOCOL = "c" * 64
_VARIANT = "full-evidence-gated-system"
_BASE = "https://schemas.unasked.dev/attestations"
_VARIANTS = (
    "deterministic-detectors-only",
    "read-only-llm-reviewer",
    "llm-tools-no-experiment-gate",
    "experiment-loop-without-falsifier",
    "full-evidence-gated-system",
)


def _private(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _policy(*, mode: str = "PRODUCTION") -> tuple[bytes, str, dict[str, Ed25519PrivateKey]]:
    roles = sorted({role for role, _ in PREDICATE_ROLES.values()})
    keys = {role: _private(80 + index) for index, role in enumerate(roles)}
    document = {
        "schema_version": "0.4.0",
        "policy_id": "policy-attestation-redteam",
        "mode": mode,
        "issued_at": "2025-01-01T00:00:00Z",
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
        "algorithm": "Ed25519",
        "dsse_payload_type": DSSE_PAYLOAD_TYPE,
        "statement_type": IN_TOTO_STATEMENT_TYPE,
        "keys": [
            {
                "key_id": f"key-{role.lower().replace('_', '-')}",
                "actor_id": f"actor-{role.lower().replace('_', '-')}",
                "role": role,
                "status": "ACTIVE",
                "public_key_base64": _public_b64(keys[role]),
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2030-01-01T00:00:00Z",
            }
            for role in roles
        ],
        "thresholds": [{"role": role, "minimum_signatures": 1} for role in roles],
        "predicate_roles": [
            {"predicate_type": predicate_type, "role": role}
            for predicate_type, (role, _) in PREDICATE_ROLES.items()
        ],
        "separation": {
            "unique_public_keys": True,
            "one_role_per_key": True,
            "distinct_actor_ids_across_roles": True,
        },
    }
    policy_bytes = canonical_json(document)
    return policy_bytes, sha256_bytes(policy_bytes), keys


def _actor(role: str) -> str:
    return f"actor-{role.lower().replace('_', '-')}"


def _sign(
    predicate_name: str,
    predicate: dict,
    subject_bytes: bytes,
    private_key: Ed25519PrivateKey,
    *,
    subjects: list[dict] | None = None,
) -> bytes:
    predicate_type = f"{_BASE}/{predicate_name}/v0.4"
    statement = canonical_json(
        {
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": subjects
            if subjects is not None
            else [
                {
                    "name": "opaque-exact-bytes",
                    "digest": {"sha256": sha256_bytes(subject_bytes)},
                }
            ],
            "predicateType": predicate_type,
            "predicate": predicate,
        }
    )
    signature = private_key.sign(dsse_pae(DSSE_PAYLOAD_TYPE, statement))
    return canonical_json(
        {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(statement).decode("ascii"),
            "signatures": [{"sig": base64.b64encode(signature).decode("ascii")}],
        }
    )


def _base(predicate_id: str, policy_sha256: str, actor_id: str) -> dict:
    return {
        "schema_version": "0.4.0",
        "predicate_id": predicate_id,
        "issued_at": "2026-01-05T00:00:00Z",
        "issuer_actor_id": actor_id,
        "trust_policy_sha256": policy_sha256,
    }


def _custody(policy_sha256: str, manifest_bytes: bytes) -> dict:
    return {
        **_base("custody-redteam", policy_sha256, _actor("CUSTODIAN")),
        "suite_id": _SUITE,
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "case_commitment_sha256": _HASH,
        "sealed_at": "2025-12-01T00:00:00Z",
        "explorer_development_started_at": "2025-12-02T00:00:00Z",
        "independent_custody": True,
        "sealed_before_explorer": True,
        "hidden_case_count": 7,
        "positive_case_count": 5,
        "control_case_count": 2,
        "explorer_ground_truth_access": False,
        "evaluator_access": False,
        "directional_steering": False,
    }


def _isolation(policy_sha256: str) -> dict:
    return {
        **_base("isolation-redteam", policy_sha256, _actor("ISOLATION_ATTESTER")),
        "suite_id": _SUITE,
        "case_id": _CASE,
        "variant": _VARIANT,
        "run_id": _RUN,
        "started_at": "2026-01-03T00:00:00Z",
        "completed_at": "2026-01-03T00:01:00Z",
        "target_snapshot_hash": _SNAPSHOT,
        "protocol_hash": _PROTOCOL,
        "executor_actor_id": "actor-executor",
        "isolation_class": "EXTERNAL_SEALED",
        "network_mode": "DENY_ALL",
        "filesystem_mode": "IMMUTABLE_INPUT_ISOLATED_OUTPUT",
        "input_manifest_sha256": _HASH,
        "command_records_sha256": _HASH,
        "output_manifest_sha256": _HASH,
        "residual_state_detected": False,
    }


def _ledger(path: Path) -> tuple[bytes, int, str]:
    ledger = EventLedger(path, run_id=_RUN)
    ledger.append(
        "RUN_CREATED",
        {"target_snapshot_hash": _SNAPSHOT, "protocol_hash": _PROTOCOL},
        occurred_at="2026-01-01T00:00:00Z",
    )
    report = ledger.verify_or_raise()
    return path.read_bytes(), report.entries, str(report.last_hash)


def _checkpoint(policy_sha256: str, ledger_bytes: bytes, entries: int, head: str) -> dict:
    return {
        **_base("checkpoint-redteam", policy_sha256, _actor("LEDGER_WITNESS")),
        "suite_id": _SUITE,
        "case_id": _CASE,
        "variant": _VARIANT,
        "run_id": _RUN,
        "entry_count": entries,
        "head_event_hash": head,
        "ledger_sha256": sha256_bytes(ledger_bytes),
        "target_snapshot_hash": _SNAPSHOT,
        "protocol_hash": _PROTOCOL,
        "checkpointed_at": "2026-01-04T00:00:00Z",
    }


def _bindings() -> list[dict]:
    return [
        {
            "variant": variant,
            "case_id": f"case-{case_number}",
            "run_id": f"run-{case_number}-{variant}",
            "target_snapshot_hash": _SNAPSHOT,
            "result_sha256": _HASH,
            "isolation_envelope_sha256": _HASH,
            "ledger_checkpoint_envelope_sha256": _HASH,
            "evidence_index_entry_sha256": _HASH,
            "certificate_set_sha256": _HASH,
        }
        for case_number in range(1, 8)
        for variant in _VARIANTS
    ]


def _evaluation(
    policy_sha256: str,
    *,
    custody_envelope: bytes,
    report: bytes,
    index: bytes,
    audit: bytes,
    matrix: bytes,
    bindings: list[dict],
) -> dict:
    return {
        **_base("evaluation-redteam", policy_sha256, _actor("TRIAL_EVALUATOR")),
        "suite_id": _SUITE,
        "manifest_sha256": sha256_bytes(b'{"sealed":"manifest"}'),
        "protocol_hash": _PROTOCOL,
        "custody_envelope_sha256": sha256_bytes(custody_envelope),
        "report_sha256": sha256_bytes(report),
        "evidence_index_sha256": sha256_bytes(index),
        "audit_sha256": sha256_bytes(audit),
        "run_matrix_sha256": sha256_bytes(matrix),
        "run_count": 35,
        "variant_count": 5,
        "case_count": 7,
        "run_bindings": bindings,
        "thresholds": {
            "positive_cases_required": 3,
            "positive_cases_total": 5,
            "control_false_verified_max": 0,
            "clean_replay_rate_required": "1.000000",
            "run_count_required": 35,
            "variant_count_required": 5,
            "case_count_required": 7,
        },
        "observed": {
            "trusted_verified_positives": 3,
            "false_verified_controls": 0,
            "false_verified_claims": 0,
            "claimed_verified_total": 3,
            "clean_replay_verified": 3,
            "context_provenance_complete": True,
            "target_snapshot_immutable": True,
            "hidden_inputs_immutable": True,
            "scoring_policy_immutable": True,
        },
        "gates": {
            "matrix_complete": True,
            "independent_custody": True,
            "sealed_before_explorer": True,
            "actor_identities_authenticated": True,
            "isolation_attestations_authenticated": True,
            "ledger_checkpoints_authenticated": True,
            "certificate_graphs_valid": True,
            "positive_threshold_met": True,
            "control_threshold_met": True,
            "clean_replay_complete": True,
            "context_provenance_complete": True,
            "inputs_immutable": True,
        },
        "status": "THRESHOLDS_MET",
    }


@dataclass(frozen=True)
class _Chain:
    policy_bytes: bytes
    policy_sha256: str
    keys: dict[str, Ed25519PrivateKey]
    manifest: bytes
    custody_envelope: bytes
    report: bytes
    index: bytes
    audit: bytes
    matrix: bytes
    bindings: list[dict]
    evaluation_envelope: bytes


def _chain(*, mode: str = "PRODUCTION") -> _Chain:
    policy_bytes, policy_sha256, keys = _policy(mode=mode)
    manifest = b'{"sealed":"manifest"}'
    custody_envelope = _sign(
        "custody",
        _custody(policy_sha256, manifest),
        manifest,
        keys["CUSTODIAN"],
    )
    report = b'{"trial":"report"}'
    index = b'{"evidence":"index"}'
    audit = b'{"audit":"pass"}'
    matrix = b'{"matrix":"35-runs"}'
    bindings = _bindings()
    evaluation_envelope = _sign(
        "trial-evaluation",
        _evaluation(
            policy_sha256,
            custody_envelope=custody_envelope,
            report=report,
            index=index,
            audit=audit,
            matrix=matrix,
            bindings=bindings,
        ),
        report,
        keys["TRIAL_EVALUATOR"],
    )
    return _Chain(
        policy_bytes,
        policy_sha256,
        keys,
        manifest,
        custody_envelope,
        report,
        index,
        audit,
        matrix,
        bindings,
        evaluation_envelope,
    )


def _certification(chain: _Chain, *, decision: str = "M0_DEMONSTRATED") -> bytes:
    claim = (
        "Demonstrated blind discovery of reproducible discrepancies on a sealed evaluation set."
        if decision == "M0_DEMONSTRATED"
        else "M0_NOT_DEMONSTRATED"
    )
    predicate = {
        **_base("certification-redteam", chain.policy_sha256, _actor("M0_CERTIFIER")),
        "suite_id": _SUITE,
        "manifest_sha256": sha256_bytes(chain.manifest),
        "protocol_hash": _PROTOCOL,
        "custody_envelope_sha256": sha256_bytes(chain.custody_envelope),
        "trial_evaluation_envelope_sha256": sha256_bytes(chain.evaluation_envelope),
        "evidence_index_sha256": sha256_bytes(chain.index),
        "audit_sha256": sha256_bytes(chain.audit),
        "run_matrix_sha256": sha256_bytes(chain.matrix),
        "decision": decision,
        "claim": claim,
        "limitations": [],
    }
    return _sign(
        "m0-certification",
        predicate,
        chain.evaluation_envelope,
        chain.keys["M0_CERTIFIER"],
    )


def _verify_certification(chain: _Chain, envelope: bytes):
    return verify_m0_certification(
        envelope,
        trust_policy_bytes=chain.policy_bytes,
        trust_policy_sha256=chain.policy_sha256,
        manifest_bytes=chain.manifest,
        custody_envelope_bytes=chain.custody_envelope,
        trial_evaluation_envelope_bytes=chain.evaluation_envelope,
        report_bytes=chain.report,
        evidence_index_bytes=chain.index,
        audit_bytes=chain.audit,
        run_matrix_bytes=chain.matrix,
        expected_suite_id=_SUITE,
        expected_manifest_sha256=sha256_bytes(chain.manifest),
        expected_protocol_hash=_PROTOCOL,
        expected_run_bindings=chain.bindings,
        now=_NOW,
    )


def test_high_level_apis_reject_handmade_policy_and_verified_statement_tokens() -> None:
    chain = _chain()
    fake_policy = TrustPolicy(b"{}", _HASH, {}, (), {}, {})
    fake_statement = VerifiedStatement(
        b"{}",
        _HASH,
        {},
        {},
        (),
        (),
        (),
        (),
        "PRODUCTION",
        True,
    )

    with pytest.raises(TypeError, match="unexpected keyword argument 'policy'"):
        verify_custody_attestation(
            chain.custody_envelope,
            trust_policy_bytes=chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            manifest_bytes=chain.manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            now=_NOW,
            policy=fake_policy,  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'verified_custody'"):
        verify_m0_certification(
            _certification(chain),
            trust_policy_bytes=chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            manifest_bytes=chain.manifest,
            custody_envelope_bytes=chain.custody_envelope,
            trial_evaluation_envelope_bytes=chain.evaluation_envelope,
            report_bytes=chain.report,
            evidence_index_bytes=chain.index,
            audit_bytes=chain.audit,
            run_matrix_bytes=chain.matrix,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            expected_protocol_hash=_PROTOCOL,
            expected_run_bindings=chain.bindings,
            now=_NOW,
            verified_custody=fake_statement,  # type: ignore[call-arg]
        )


def test_high_level_api_reloads_and_exactly_pins_policy_bytes() -> None:
    chain = _chain()

    with pytest.raises(IntegrityError, match="exact-byte"):
        verify_custody_attestation(
            chain.custody_envelope,
            trust_policy_bytes=b"\n" + chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            manifest_bytes=chain.manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            now=_NOW,
        )


def test_subject_requires_exactly_one_sha256_but_allows_unknown_digest_algorithms() -> None:
    policy_bytes, policy_sha256, keys = _policy()
    manifest = b"manifest-exact"
    predicate = _custody(policy_sha256, manifest)
    valid_subject = {
        "name": "manifest",
        "digest": {"sha256": sha256_bytes(manifest), "sha512": "forward-compatible"},
    }
    compatible = _sign(
        "custody",
        predicate,
        manifest,
        keys["CUSTODIAN"],
        subjects=[valid_subject],
    )
    assert verify_custody_attestation(
        compatible,
        trust_policy_bytes=policy_bytes,
        trust_policy_sha256=policy_sha256,
        manifest_bytes=manifest,
        expected_suite_id=_SUITE,
        expected_manifest_sha256=sha256_bytes(manifest),
        now=_NOW,
    ).production_qualified

    multiple = _sign(
        "custody",
        predicate,
        manifest,
        keys["CUSTODIAN"],
        subjects=[valid_subject, valid_subject],
    )
    with pytest.raises(IntegrityError, match="exactly one subject"):
        verify_custody_attestation(
            multiple,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            manifest_bytes=manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(manifest),
            now=_NOW,
        )

    wrong_sha = _sign(
        "custody",
        predicate,
        manifest,
        keys["CUSTODIAN"],
        subjects=[{"name": "manifest", "digest": {"sha256": _HASH}}],
    )
    with pytest.raises(IntegrityError, match="subject digest"):
        verify_custody_attestation(
            wrong_sha,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            manifest_bytes=manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(manifest),
            now=_NOW,
        )


def test_custody_predicate_manifest_hash_cannot_disagree_with_exact_manifest() -> None:
    policy_bytes, policy_sha256, keys = _policy()
    manifest = b"manifest-exact"
    predicate = _custody(policy_sha256, manifest)
    predicate["manifest_sha256"] = _HASH
    envelope = _sign("custody", predicate, manifest, keys["CUSTODIAN"])

    with pytest.raises(IntegrityError, match="caller-expected binding"):
        verify_custody_attestation(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            manifest_bytes=manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(manifest),
            now=_NOW,
        )


def test_custody_subject_digest_cannot_be_swapped_even_when_predicate_fields_match() -> None:
    policy_bytes, policy_sha256, keys = _policy()
    signed_subject = b"sealed-manifest-a"
    supplied_manifest = b"sealed-manifest-b"
    predicate = _custody(policy_sha256, supplied_manifest)
    envelope = _sign("custody", predicate, signed_subject, keys["CUSTODIAN"])

    with pytest.raises(IntegrityError, match="subject digest"):
        verify_custody_attestation(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            manifest_bytes=supplied_manifest,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(supplied_manifest),
            now=_NOW,
        )


@pytest.mark.parametrize(
    ("argument", "wrong_value"),
    [
        ("expected_suite_id", "suite-wrong"),
        ("expected_case_id", "case-wrong"),
        ("expected_variant", "read-only-llm-reviewer"),
        ("expected_run_id", "run-wrong"),
        ("expected_target_snapshot_hash", "d" * 64),
        ("expected_protocol_hash", "e" * 64),
    ],
)
def test_isolation_identity_and_protocol_bindings_cannot_be_swapped(
    argument: str,
    wrong_value: str,
) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    result = b'{"result":"exact"}'
    envelope = _sign("isolation", _isolation(policy_sha256), result, keys["ISOLATION_ATTESTER"])
    arguments = {
        "expected_suite_id": _SUITE,
        "expected_case_id": _CASE,
        "expected_variant": _VARIANT,
        "expected_run_id": _RUN,
        "expected_target_snapshot_hash": _SNAPSHOT,
        "expected_protocol_hash": _PROTOCOL,
    }
    arguments[argument] = wrong_value

    with pytest.raises(IntegrityError, match="caller-expected binding"):
        verify_isolation_attestation(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            result_bytes=result,
            now=_NOW,
            **arguments,
        )


def test_old_valid_checkpoint_cannot_authenticate_the_current_longer_ledger(tmp_path: Path) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    ledger_path = tmp_path / "events.jsonl"
    old_bytes, entries, head = _ledger(ledger_path)
    envelope = _sign(
        "ledger-checkpoint",
        _checkpoint(policy_sha256, old_bytes, entries, head),
        old_bytes,
        keys["LEDGER_WITNESS"],
    )
    EventLedger(ledger_path, run_id=_RUN).append(
        "ARTIFACT_IMPORTED",
        {"sha256": _HASH},
        occurred_at="2026-01-02T00:00:00Z",
    )
    current_bytes = ledger_path.read_bytes()

    with pytest.raises(IntegrityError, match="subject digest"):
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=current_bytes,
            expected_suite_id=_SUITE,
            expected_case_id=_CASE,
            expected_variant=_VARIANT,
            expected_run_id=_RUN,
            expected_target_snapshot_hash=_SNAPSHOT,
            expected_protocol_hash=_PROTOCOL,
            now=_NOW,
        )


def test_same_length_ledger_fork_cannot_reuse_a_valid_checkpoint(tmp_path: Path) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    base_path = tmp_path / "base.jsonl"
    base_bytes, _, _ = _ledger(base_path)
    first_path = tmp_path / "first.jsonl"
    second_path = tmp_path / "second.jsonl"
    first_path.write_bytes(base_bytes)
    second_path.write_bytes(base_bytes)
    EventLedger(first_path, run_id=_RUN).append(
        "ARTIFACT_IMPORTED", {"branch": "first"}, occurred_at="2026-01-02T00:00:00Z"
    )
    EventLedger(second_path, run_id=_RUN).append(
        "ARTIFACT_IMPORTED", {"branch": "second"}, occurred_at="2026-01-02T00:00:00Z"
    )
    first_bytes = first_path.read_bytes()
    report = EventLedger(first_path, run_id=_RUN).verify_or_raise()
    envelope = _sign(
        "ledger-checkpoint",
        _checkpoint(policy_sha256, first_bytes, report.entries, str(report.last_hash)),
        first_bytes,
        keys["LEDGER_WITNESS"],
    )

    with pytest.raises(IntegrityError, match="subject digest"):
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=second_path.read_bytes(),
            expected_suite_id=_SUITE,
            expected_case_id=_CASE,
            expected_variant=_VARIANT,
            expected_run_id=_RUN,
            expected_target_snapshot_hash=_SNAPSHOT,
            expected_protocol_hash=_PROTOCOL,
            now=_NOW,
        )


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("entry_count", 2),
        ("head_event_hash", _HASH),
        ("run_id", "run-wrong"),
        ("target_snapshot_hash", "d" * 64),
        ("protocol_hash", "e" * 64),
    ],
)
def test_checkpoint_count_head_run_snapshot_and_protocol_are_all_bound(
    tmp_path: Path,
    field: str,
    wrong_value: object,
) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    ledger_bytes, entries, head = _ledger(tmp_path / "events.jsonl")
    predicate = _checkpoint(policy_sha256, ledger_bytes, entries, head)
    predicate[field] = wrong_value
    envelope = _sign("ledger-checkpoint", predicate, ledger_bytes, keys["LEDGER_WITNESS"])

    with pytest.raises(IntegrityError, match="binding"):
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=ledger_bytes,
            expected_suite_id=_SUITE,
            expected_case_id=_CASE,
            expected_variant=_VARIANT,
            expected_run_id=_RUN,
            expected_target_snapshot_hash=_SNAPSHOT,
            expected_protocol_hash=_PROTOCOL,
            now=_NOW,
        )


def test_checkpoint_signature_cannot_make_a_tampered_ledger_valid(tmp_path: Path) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    ledger_bytes, entries, head = _ledger(tmp_path / "events.jsonl")
    tampered = ledger_bytes.replace(b'"protocol_hash":"', b'"protocol_hash":"f', 1)
    predicate = _checkpoint(policy_sha256, tampered, entries, head)
    envelope = _sign("ledger-checkpoint", predicate, tampered, keys["LEDGER_WITNESS"])

    with pytest.raises(IntegrityError):
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=tampered,
            expected_suite_id=_SUITE,
            expected_case_id=_CASE,
            expected_variant=_VARIANT,
            expected_run_id=_RUN,
            expected_target_snapshot_hash=_SNAPSHOT,
            expected_protocol_hash=_PROTOCOL,
            now=_NOW,
        )


@pytest.mark.parametrize("initial_field", ["target_snapshot_hash", "protocol_hash"])
def test_checkpoint_predicate_cannot_override_wrong_initial_run_binding(
    tmp_path: Path,
    initial_field: str,
) -> None:
    policy_bytes, policy_sha256, keys = _policy()
    ledger_path = tmp_path / "events.jsonl"
    payload = {"target_snapshot_hash": _SNAPSHOT, "protocol_hash": _PROTOCOL}
    payload[initial_field] = "d" * 64
    ledger = EventLedger(ledger_path, run_id=_RUN)
    ledger.append("RUN_CREATED", payload, occurred_at="2026-01-01T00:00:00Z")
    report = ledger.verify_or_raise()
    ledger_bytes = ledger_path.read_bytes()
    predicate = _checkpoint(policy_sha256, ledger_bytes, report.entries, str(report.last_hash))
    envelope = _sign("ledger-checkpoint", predicate, ledger_bytes, keys["LEDGER_WITNESS"])

    with pytest.raises(IntegrityError) as caught:
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=ledger_bytes,
            expected_suite_id=_SUITE,
            expected_case_id=_CASE,
            expected_variant=_VARIANT,
            expected_run_id=_RUN,
            expected_target_snapshot_hash=_SNAPSHOT,
            expected_protocol_hash=_PROTOCOL,
            now=_NOW,
        )
    assert caught.value.details["field"] == f"RUN_CREATED.{initial_field}"


@pytest.mark.parametrize("matrix_attack", ["omission", "duplicate", "reuse_run"])
def test_trial_evaluation_rejects_matrix_omission_duplicate_and_run_reuse(
    matrix_attack: str,
) -> None:
    chain = _chain()
    attacked = list(chain.bindings)
    if matrix_attack == "omission":
        attacked = attacked[:-1]
    elif matrix_attack == "duplicate":
        attacked[-1] = dict(attacked[0])
        attacked[-1]["run_id"] = "run-duplicate-pair"
    else:
        attacked[-1] = {**attacked[-1], "run_id": attacked[0]["run_id"]}
    predicate = _evaluation(
        chain.policy_sha256,
        custody_envelope=chain.custody_envelope,
        report=chain.report,
        index=chain.index,
        audit=chain.audit,
        matrix=chain.matrix,
        bindings=attacked,
    )
    envelope = _sign(
        "trial-evaluation",
        predicate,
        chain.report,
        chain.keys["TRIAL_EVALUATOR"],
    )

    with pytest.raises((IntegrityError, SchemaValidationError)):
        verify_trial_evaluation(
            envelope,
            trust_policy_bytes=chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            custody_envelope_bytes=chain.custody_envelope,
            report_bytes=chain.report,
            evidence_index_bytes=chain.index,
            audit_bytes=chain.audit,
            run_matrix_bytes=chain.matrix,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            expected_protocol_hash=_PROTOCOL,
            expected_run_bindings=attacked,
            now=_NOW,
        )


@pytest.mark.parametrize(
    "field",
    [
        "custody_envelope_sha256",
        "report_sha256",
        "evidence_index_sha256",
        "audit_sha256",
        "run_matrix_sha256",
    ],
)
def test_trial_evaluation_exact_byte_references_cannot_be_replaced(field: str) -> None:
    chain = _chain()
    predicate = _evaluation(
        chain.policy_sha256,
        custody_envelope=chain.custody_envelope,
        report=chain.report,
        index=chain.index,
        audit=chain.audit,
        matrix=chain.matrix,
        bindings=chain.bindings,
    )
    predicate[field] = _HASH
    envelope = _sign("trial-evaluation", predicate, chain.report, chain.keys["TRIAL_EVALUATOR"])

    with pytest.raises(IntegrityError, match="caller-expected binding"):
        verify_trial_evaluation(
            envelope,
            trust_policy_bytes=chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            custody_envelope_bytes=chain.custody_envelope,
            report_bytes=chain.report,
            evidence_index_bytes=chain.index,
            audit_bytes=chain.audit,
            run_matrix_bytes=chain.matrix,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            expected_protocol_hash=_PROTOCOL,
            expected_run_bindings=chain.bindings,
            now=_NOW,
        )


def test_trial_evaluation_signed_bindings_must_equal_caller_recomputed_bindings() -> None:
    chain = _chain()
    expected = [dict(item) for item in chain.bindings]
    expected[0]["evidence_index_entry_sha256"] = "d" * 64

    with pytest.raises(IntegrityError) as caught:
        verify_trial_evaluation(
            chain.evaluation_envelope,
            trust_policy_bytes=chain.policy_bytes,
            trust_policy_sha256=chain.policy_sha256,
            custody_envelope_bytes=chain.custody_envelope,
            report_bytes=chain.report,
            evidence_index_bytes=chain.index,
            audit_bytes=chain.audit,
            run_matrix_bytes=chain.matrix,
            expected_suite_id=_SUITE,
            expected_manifest_sha256=sha256_bytes(chain.manifest),
            expected_protocol_hash=_PROTOCOL,
            expected_run_bindings=expected,
            now=_NOW,
        )
    assert caught.value.details["field"] == "run_bindings"


def test_full_production_chain_can_demonstrate_but_not_boolean_launder_not_demonstrated() -> None:
    chain = _chain()
    demonstrated = _verify_certification(chain, _certification(chain))
    not_demonstrated = _verify_certification(
        chain, _certification(chain, decision="M0_NOT_DEMONSTRATED")
    )

    assert demonstrated.demonstrated is True
    assert demonstrated.reason == "M0_DEMONSTRATED"
    assert not_demonstrated.demonstrated is False
    assert not_demonstrated.reason == "M0_NOT_DEMONSTRATED"


def test_shadow_signed_full_chain_cannot_launder_m0_demonstrated() -> None:
    chain = _chain(mode="SHADOW")

    with pytest.raises(IntegrityError, match="lacks complete production-qualified inputs"):
        _verify_certification(chain, _certification(chain))


def test_m0_certification_reverifies_nested_envelopes_instead_of_trusting_outer_hashes() -> None:
    chain = _chain()
    envelope = _certification(chain)
    tampered_custody = chain.custody_envelope + b"\n"
    attacked = _Chain(
        chain.policy_bytes,
        chain.policy_sha256,
        chain.keys,
        chain.manifest,
        tampered_custody,
        chain.report,
        chain.index,
        chain.audit,
        chain.matrix,
        chain.bindings,
        chain.evaluation_envelope,
    )

    with pytest.raises(IntegrityError, match="caller-expected binding"):
        _verify_certification(attacked, envelope)


def test_m0_certification_rejects_nested_custody_self_signed_by_untrusted_key() -> None:
    chain = _chain()
    attacker = _private(120)
    attacker_custody = _sign(
        "custody",
        _custody(chain.policy_sha256, chain.manifest),
        chain.manifest,
        attacker,
    )
    evaluation = _evaluation(
        chain.policy_sha256,
        custody_envelope=attacker_custody,
        report=chain.report,
        index=chain.index,
        audit=chain.audit,
        matrix=chain.matrix,
        bindings=chain.bindings,
    )
    evaluation_envelope = _sign(
        "trial-evaluation",
        evaluation,
        chain.report,
        chain.keys["TRIAL_EVALUATOR"],
    )
    attacked = _Chain(
        chain.policy_bytes,
        chain.policy_sha256,
        chain.keys,
        chain.manifest,
        attacker_custody,
        chain.report,
        chain.index,
        chain.audit,
        chain.matrix,
        chain.bindings,
        evaluation_envelope,
    )

    with pytest.raises(IntegrityError, match="threshold"):
        _verify_certification(attacked, _certification(attacked))
