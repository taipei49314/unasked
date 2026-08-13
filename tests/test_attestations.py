from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unasked.attestations import (
    read_exact_bytes,
    verify_custody_attestation,
    verify_isolation_attestation,
    verify_ledger_checkpoint,
    verify_m0_certification,
    verify_trial_evaluation,
)
from unasked.errors import IntegrityError
from unasked.ledger import EventLedger
from unasked.trust import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    PREDICATE_ROLES,
    dsse_pae,
)
from unasked.util import canonical_json, sha256_bytes

NOW = "2026-08-13T08:00:00Z"
ISSUED = "2026-08-13T07:00:00Z"
HASH = "a" * 64
SUITE = "suite-1"
MANIFEST = b'{"opaque":"sealed-manifest"}'
REPORT = b'{"trial":"report"}'
INDEX = b'{"evidence":"index"}'
AUDIT = b'{"audit":"pass"}'
MATRIX = b'{"matrix":"5x7"}'
RESULT = b'{"result":"isolated"}'
SNAPSHOT = "b" * 64
PROTOCOL = "c" * 64


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _policy() -> tuple[bytes, str, dict[str, Ed25519PrivateKey]]:
    keys = []
    thresholds = []
    mappings = []
    private_keys = {}
    for index, (predicate_type, (role, _)) in enumerate(PREDICATE_ROLES.items(), start=1):
        private = Ed25519PrivateKey.from_private_bytes(bytes([60 + index]) * 32)
        private_keys[role] = private
        keys.append(
            {
                "key_id": f"key-{index}",
                "actor_id": f"actor-{index}",
                "role": role,
                "status": "ACTIVE",
                "public_key_base64": base64.b64encode(_raw_public_key(private)).decode(),
                "valid_from": "2026-08-01T00:00:00Z",
                "valid_until": "2026-09-01T00:00:00Z",
            }
        )
        thresholds.append({"role": role, "minimum_signatures": 1})
        mappings.append({"predicate_type": predicate_type, "role": role})
    document = {
        "schema_version": "0.4.0",
        "policy_id": "policy-1",
        "mode": "PRODUCTION",
        "issued_at": "2026-08-01T00:00:00Z",
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2026-09-01T00:00:00Z",
        "algorithm": "Ed25519",
        "dsse_payload_type": DSSE_PAYLOAD_TYPE,
        "statement_type": IN_TOTO_STATEMENT_TYPE,
        "keys": keys,
        "thresholds": thresholds,
        "predicate_roles": mappings,
        "separation": {
            "unique_public_keys": True,
            "one_role_per_key": True,
            "distinct_actor_ids_across_roles": True,
        },
    }
    encoded = canonical_json(document)
    return encoded, sha256_bytes(encoded), private_keys


def _envelope(
    predicate_type: str,
    predicate: dict,
    subject_bytes: bytes,
    private_key: Ed25519PrivateKey,
    *,
    subject_sha256: str | None = None,
) -> bytes:
    payload = canonical_json(
        {
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [
                {
                    "name": "description-not-authority",
                    "digest": {
                        "sha256": subject_sha256 or sha256_bytes(subject_bytes),
                        "futureDigest": "ignored",
                    },
                }
            ],
            "predicateType": predicate_type,
            "predicate": predicate,
        }
    )
    signature = private_key.sign(dsse_pae(DSSE_PAYLOAD_TYPE, payload))
    return canonical_json(
        {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"sig": base64.b64encode(signature).decode()}],
        }
    )


def _common(policy_sha256: str, issuer: str) -> dict:
    return {
        "schema_version": "0.4.0",
        "predicate_id": f"predicate-{issuer}",
        "issued_at": ISSUED,
        "issuer_actor_id": issuer,
        "trust_policy_sha256": policy_sha256,
    }


def _custody_predicate(policy_sha256: str) -> dict:
    return {
        **_common(policy_sha256, "actor-2"),
        "suite_id": SUITE,
        "manifest_sha256": sha256_bytes(MANIFEST),
        "case_commitment_sha256": HASH,
        "sealed_at": "2026-08-10T00:00:00Z",
        "explorer_development_started_at": "2026-08-11T00:00:00Z",
        "independent_custody": True,
        "sealed_before_explorer": True,
        "hidden_case_count": 7,
        "positive_case_count": 5,
        "control_case_count": 2,
        "explorer_ground_truth_access": False,
        "evaluator_access": False,
        "directional_steering": False,
    }


def _bindings() -> list[dict]:
    variants = (
        "deterministic-detectors-only",
        "read-only-llm-reviewer",
        "llm-tools-no-experiment-gate",
        "experiment-loop-without-falsifier",
        "full-evidence-gated-system",
    )
    return [
        {
            "variant": variant,
            "case_id": f"case-{case}",
            "run_id": f"run-{variant}-{case}",
            "target_snapshot_hash": SNAPSHOT,
            "result_sha256": HASH,
            "isolation_envelope_sha256": HASH,
            "ledger_checkpoint_envelope_sha256": HASH,
            "evidence_index_entry_sha256": HASH,
            "certificate_set_sha256": HASH,
        }
        for variant in variants
        for case in range(1, 8)
    ]


def _evaluation_predicate(policy_sha256: str, custody_envelope: bytes) -> dict:
    gates = {
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
    }
    return {
        **_common(policy_sha256, "actor-5"),
        "suite_id": SUITE,
        "manifest_sha256": sha256_bytes(MANIFEST),
        "protocol_hash": PROTOCOL,
        "custody_envelope_sha256": sha256_bytes(custody_envelope),
        "report_sha256": sha256_bytes(REPORT),
        "evidence_index_sha256": sha256_bytes(INDEX),
        "audit_sha256": sha256_bytes(AUDIT),
        "run_matrix_sha256": sha256_bytes(MATRIX),
        "run_count": 35,
        "variant_count": 5,
        "case_count": 7,
        "run_bindings": _bindings(),
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
        "gates": gates,
        "status": "THRESHOLDS_MET",
    }


@dataclass(frozen=True)
class SignedTrial:
    policy_bytes: bytes
    policy_sha256: str
    custody_envelope: bytes
    evaluation_envelope: bytes
    certification_envelope: bytes


def _signed_trial() -> SignedTrial:
    policy_bytes, policy_sha256, keys = _policy()
    custody_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    custody = _envelope(
        custody_type, _custody_predicate(policy_sha256), MANIFEST, keys["CUSTODIAN"]
    )
    evaluation_type = "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4"
    evaluation = _envelope(
        evaluation_type,
        _evaluation_predicate(policy_sha256, custody),
        REPORT,
        keys["TRIAL_EVALUATOR"],
    )
    certification_type = "https://schemas.unasked.dev/attestations/m0-certification/v0.4"
    certification = _envelope(
        certification_type,
        {
            **_common(policy_sha256, "actor-6"),
            "suite_id": SUITE,
            "manifest_sha256": sha256_bytes(MANIFEST),
            "protocol_hash": PROTOCOL,
            "custody_envelope_sha256": sha256_bytes(custody),
            "trial_evaluation_envelope_sha256": sha256_bytes(evaluation),
            "evidence_index_sha256": sha256_bytes(INDEX),
            "audit_sha256": sha256_bytes(AUDIT),
            "run_matrix_sha256": sha256_bytes(MATRIX),
            "decision": "M0_DEMONSTRATED",
            "claim": (
                "Demonstrated blind discovery of reproducible discrepancies on a sealed "
                "evaluation set."
            ),
            "limitations": [],
        },
        evaluation,
        keys["M0_CERTIFIER"],
    )
    return SignedTrial(policy_bytes, policy_sha256, custody, evaluation, certification)


def test_exact_file_loader_returns_one_byte_buffer_and_rejects_non_file(tmp_path: Path) -> None:
    path = tmp_path / "evidence.dsse"
    path.write_bytes(b"exact bytes")
    assert read_exact_bytes(path) == b"exact bytes"
    with pytest.raises(Exception, match="regular file|could not be read"):
        read_exact_bytes(tmp_path)


def test_custody_binds_external_pin_manifest_subject_and_expected_identity() -> None:
    trial = _signed_trial()
    verified = verify_custody_attestation(
        trial.custody_envelope,
        trust_policy_bytes=trial.policy_bytes,
        trust_policy_sha256=trial.policy_sha256,
        manifest_bytes=MANIFEST,
        expected_suite_id=SUITE,
        expected_manifest_sha256=sha256_bytes(MANIFEST),
        now=NOW,
    )
    assert verified.production_qualified

    with pytest.raises(IntegrityError, match="subject digest"):
        verify_custody_attestation(
            trial.custody_envelope,
            trust_policy_bytes=trial.policy_bytes,
            trust_policy_sha256=trial.policy_sha256,
            manifest_bytes=b"different manifest",
            expected_suite_id=SUITE,
            expected_manifest_sha256=sha256_bytes(b"different manifest"),
            now=NOW,
        )
    with pytest.raises(IntegrityError, match="exact-byte"):
        verify_custody_attestation(
            trial.custody_envelope,
            trust_policy_bytes=trial.policy_bytes,
            trust_policy_sha256="0" * 64,
            manifest_bytes=MANIFEST,
            expected_suite_id=SUITE,
            expected_manifest_sha256=sha256_bytes(MANIFEST),
            now=NOW,
        )


def test_isolation_binds_result_bytes_and_all_run_identity_fields() -> None:
    policy_bytes, policy_sha256, keys = _policy()
    predicate_type = "https://schemas.unasked.dev/attestations/isolation/v0.4"
    predicate = {
        **_common(policy_sha256, "actor-3"),
        "suite_id": SUITE,
        "case_id": "case-1",
        "variant": "deterministic-detectors-only",
        "run_id": "run-1",
        "started_at": "2026-08-13T06:00:00Z",
        "completed_at": ISSUED,
        "target_snapshot_hash": SNAPSHOT,
        "protocol_hash": PROTOCOL,
        "executor_actor_id": "external-executor",
        "isolation_class": "EXTERNAL_SEALED",
        "network_mode": "DENY_ALL",
        "filesystem_mode": "IMMUTABLE_INPUT_ISOLATED_OUTPUT",
        "input_manifest_sha256": HASH,
        "command_records_sha256": HASH,
        "output_manifest_sha256": HASH,
        "residual_state_detected": False,
    }
    envelope = _envelope(predicate_type, predicate, RESULT, keys["ISOLATION_ATTESTER"])
    verified = verify_isolation_attestation(
        envelope,
        trust_policy_bytes=policy_bytes,
        trust_policy_sha256=policy_sha256,
        result_bytes=RESULT,
        expected_suite_id=SUITE,
        expected_case_id="case-1",
        expected_variant="deterministic-detectors-only",
        expected_run_id="run-1",
        expected_target_snapshot_hash=SNAPSHOT,
        expected_protocol_hash=PROTOCOL,
        now=NOW,
    )
    assert verified.production_qualified
    with pytest.raises(IntegrityError, match="caller-expected binding"):
        verify_isolation_attestation(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            result_bytes=RESULT,
            expected_suite_id=SUITE,
            expected_case_id="different-case",
            expected_variant="deterministic-detectors-only",
            expected_run_id="run-1",
            expected_target_snapshot_hash=SNAPSHOT,
            expected_protocol_hash=PROTOCOL,
            now=NOW,
        )


def test_checkpoint_recomputes_exact_ledger_chain_count_head_and_creation_bindings(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "events.jsonl"
    ledger = EventLedger(ledger_path, run_id="run-1")
    ledger.append(
        "RUN_CREATED",
        {"target_snapshot_hash": SNAPSHOT, "protocol_hash": PROTOCOL},
        occurred_at=ISSUED,
    )
    ledger.append("RUN_STARTED", {}, occurred_at=ISSUED)
    ledger_bytes = ledger_path.read_bytes()
    report = ledger.verify()
    policy_bytes, policy_sha256, keys = _policy()
    predicate_type = "https://schemas.unasked.dev/attestations/ledger-checkpoint/v0.4"
    predicate = {
        **_common(policy_sha256, "actor-4"),
        "suite_id": SUITE,
        "case_id": "case-1",
        "variant": "deterministic-detectors-only",
        "run_id": "run-1",
        "entry_count": report.entries,
        "head_event_hash": report.last_hash,
        "ledger_sha256": sha256_bytes(ledger_bytes),
        "target_snapshot_hash": SNAPSHOT,
        "protocol_hash": PROTOCOL,
        "checkpointed_at": ISSUED,
    }
    envelope = _envelope(predicate_type, predicate, ledger_bytes, keys["LEDGER_WITNESS"])
    verified = verify_ledger_checkpoint(
        envelope,
        trust_policy_bytes=policy_bytes,
        trust_policy_sha256=policy_sha256,
        ledger_bytes=ledger_bytes,
        expected_suite_id=SUITE,
        expected_case_id="case-1",
        expected_variant="deterministic-detectors-only",
        expected_run_id="run-1",
        expected_target_snapshot_hash=SNAPSHOT,
        expected_protocol_hash=PROTOCOL,
        now=NOW,
    )
    assert verified.production_qualified
    with pytest.raises(IntegrityError):
        verify_ledger_checkpoint(
            envelope,
            trust_policy_bytes=policy_bytes,
            trust_policy_sha256=policy_sha256,
            ledger_bytes=ledger_bytes.replace(b"RUN_STARTED", b"RUN_STOPPED"),
            expected_suite_id=SUITE,
            expected_case_id="case-1",
            expected_variant="deterministic-detectors-only",
            expected_run_id="run-1",
            expected_target_snapshot_hash=SNAPSHOT,
            expected_protocol_hash=PROTOCOL,
            now=NOW,
        )


def test_trial_evaluation_binds_all_exact_references_and_matrix() -> None:
    trial = _signed_trial()
    verified = verify_trial_evaluation(
        trial.evaluation_envelope,
        trust_policy_bytes=trial.policy_bytes,
        trust_policy_sha256=trial.policy_sha256,
        custody_envelope_bytes=trial.custody_envelope,
        report_bytes=REPORT,
        evidence_index_bytes=INDEX,
        audit_bytes=AUDIT,
        run_matrix_bytes=MATRIX,
        expected_suite_id=SUITE,
        expected_manifest_sha256=sha256_bytes(MANIFEST),
        expected_protocol_hash=PROTOCOL,
        expected_run_bindings=_bindings(),
        now=NOW,
    )
    assert verified.production_qualified
    with pytest.raises(IntegrityError, match="caller-expected binding"):
        verify_trial_evaluation(
            trial.evaluation_envelope,
            trust_policy_bytes=trial.policy_bytes,
            trust_policy_sha256=trial.policy_sha256,
            custody_envelope_bytes=trial.custody_envelope,
            report_bytes=REPORT,
            evidence_index_bytes=b"other index",
            audit_bytes=AUDIT,
            run_matrix_bytes=MATRIX,
            expected_suite_id=SUITE,
            expected_manifest_sha256=sha256_bytes(MANIFEST),
            expected_protocol_hash=PROTOCOL,
            expected_run_bindings=_bindings(),
            now=NOW,
        )


def test_m0_certification_recursively_reverifies_custody_and_evaluation_envelopes() -> None:
    trial = _signed_trial()
    verified = verify_m0_certification(
        trial.certification_envelope,
        trust_policy_bytes=trial.policy_bytes,
        trust_policy_sha256=trial.policy_sha256,
        manifest_bytes=MANIFEST,
        custody_envelope_bytes=trial.custody_envelope,
        trial_evaluation_envelope_bytes=trial.evaluation_envelope,
        report_bytes=REPORT,
        evidence_index_bytes=INDEX,
        audit_bytes=AUDIT,
        run_matrix_bytes=MATRIX,
        expected_suite_id=SUITE,
        expected_manifest_sha256=sha256_bytes(MANIFEST),
        expected_protocol_hash=PROTOCOL,
        expected_run_bindings=_bindings(),
        now=NOW,
    )
    assert verified.demonstrated
    assert verified.reason == "M0_DEMONSTRATED"

    with pytest.raises(IntegrityError):
        verify_m0_certification(
            trial.certification_envelope,
            trust_policy_bytes=trial.policy_bytes,
            trust_policy_sha256=trial.policy_sha256,
            manifest_bytes=b"substituted",
            custody_envelope_bytes=trial.custody_envelope,
            trial_evaluation_envelope_bytes=trial.evaluation_envelope,
            report_bytes=REPORT,
            evidence_index_bytes=INDEX,
            audit_bytes=AUDIT,
            run_matrix_bytes=MATRIX,
            expected_suite_id=SUITE,
            expected_manifest_sha256=sha256_bytes(MANIFEST),
            expected_protocol_hash=PROTOCOL,
            expected_run_bindings=_bindings(),
            now=NOW,
        )
