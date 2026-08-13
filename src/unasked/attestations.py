"""Higher-level verification for externally signed UNASKED evidence.

Every verifier binds a DSSE-authenticated predicate to caller-supplied exact bytes and
expected identities.  This module never signs evidence and never treats subject names,
envelope key IDs, or SHADOW policy output as production authority.
"""

from __future__ import annotations

import hmac
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from unasked.errors import IntegrityError, UsageError
from unasked.ledger import EventLedger
from unasked.trust import (
    TrustPolicy,
    VerifiedStatement,
    load_trust_policy,
    verify_dsse_statement,
)
from unasked.util import sha256_bytes

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PREDICATE_BASE = "https://schemas.unasked.dev/attestations"


@dataclass(frozen=True, slots=True)
class CertificationVerification:
    """Authenticated M0 certification result without claim laundering."""

    statement: VerifiedStatement
    demonstrated: bool
    reason: str


def read_exact_bytes(path: str | Path) -> bytes:
    """Read a regular file once; callers retain and verify this exact byte buffer."""

    selected = Path(path)
    try:
        with selected.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise UsageError("Attestation input path must identify a regular file.")
            return stream.read()
    except UsageError:
        raise
    except OSError as exc:
        raise UsageError(
            "Attestation input bytes could not be read.", details={"path": str(selected)}
        ) from exc


def _expect_equal(actual: Any, expected: Any, field: str) -> None:
    if actual != expected:
        raise IntegrityError(
            "Authenticated attestation does not match a caller-expected binding.",
            details={"field": field, "expected": expected, "actual": actual},
        )


def _digest(value: bytes, field: str) -> str:
    if not isinstance(value, bytes):
        raise UsageError(f"{field} must be exact bytes.")
    return sha256_bytes(value)


def _verify_subject(statement: VerifiedStatement, subject_bytes: bytes) -> None:
    subject = statement.statement["subject"]
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        raise IntegrityError("Signed in-toto Statement must contain exactly one subject.")
    item = subject[0]
    if not isinstance(item.get("name"), str) or not item["name"]:
        raise UsageError("Signed in-toto subject name must be a non-empty string.")
    digests = item.get("digest")
    if not isinstance(digests, dict):
        raise UsageError("Signed in-toto subject must contain a digest object.")
    actual = digests.get("sha256")
    if not isinstance(actual, str) or not _SHA256_RE.fullmatch(actual):
        raise UsageError("Signed in-toto subject sha256 must be 64 lowercase hex characters.")
    expected = _digest(subject_bytes, "subject_bytes")
    if not hmac.compare_digest(actual, expected):
        raise IntegrityError(
            "Signed in-toto subject digest does not match the exact expected bytes.",
            details={"expected": expected, "actual": actual},
        )


def _verify(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    now: datetime | str | None,
    predicate_name: str,
    predicate_schema: str,
    subject_bytes: bytes,
) -> tuple[VerifiedStatement, TrustPolicy]:
    policy = load_trust_policy(
        trust_policy_bytes,
        expected_sha256=trust_policy_sha256,
        now=now,
    )
    predicate_type = f"{_PREDICATE_BASE}/{predicate_name}/v0.4"
    verified = verify_dsse_statement(
        envelope_bytes,
        expected_predicate_type=predicate_type,
        trusted_keys=policy.keys_for(predicate_type),
        threshold=policy.threshold_for(predicate_type),
        predicate_schema=predicate_schema,
    )
    _expect_equal(verified.predicate["trust_policy_sha256"], policy.sha256, "trust_policy_sha256")
    _verify_subject(verified, subject_bytes)
    return verified, policy


def verify_custody_attestation(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    manifest_bytes: bytes,
    expected_suite_id: str,
    expected_manifest_sha256: str,
    now: datetime | str | None = None,
) -> VerifiedStatement:
    _expect_equal(
        _digest(manifest_bytes, "manifest_bytes"),
        expected_manifest_sha256,
        "expected_manifest_sha256",
    )
    verified, _ = _verify(
        envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        now=now,
        predicate_name="custody",
        predicate_schema="custody-attestation-predicate",
        subject_bytes=manifest_bytes,
    )
    predicate = verified.predicate
    _expect_equal(predicate["suite_id"], expected_suite_id, "suite_id")
    _expect_equal(predicate["manifest_sha256"], expected_manifest_sha256, "manifest_sha256")
    return verified


def verify_isolation_attestation(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    result_bytes: bytes,
    expected_suite_id: str,
    expected_case_id: str,
    expected_variant: str,
    expected_run_id: str,
    expected_target_snapshot_hash: str,
    expected_protocol_hash: str,
    now: datetime | str | None = None,
) -> VerifiedStatement:
    verified, _ = _verify(
        envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        now=now,
        predicate_name="isolation",
        predicate_schema="isolation-attestation-predicate",
        subject_bytes=result_bytes,
    )
    predicate = verified.predicate
    expected = {
        "suite_id": expected_suite_id,
        "case_id": expected_case_id,
        "variant": expected_variant,
        "run_id": expected_run_id,
        "target_snapshot_hash": expected_target_snapshot_hash,
        "protocol_hash": expected_protocol_hash,
    }
    for field, value in expected.items():
        _expect_equal(predicate[field], value, field)
    return verified


def _verify_ledger_bytes(
    ledger_bytes: bytes,
    *,
    run_id: str,
) -> tuple[int, str]:
    _digest(ledger_bytes, "ledger_bytes")
    with tempfile.TemporaryDirectory(prefix="unasked-ledger-verify-") as directory:
        path = Path(directory) / "events.jsonl"
        path.write_bytes(ledger_bytes)
        report = EventLedger(path, run_id=run_id).verify(raise_on_error=True)
        records = EventLedger(path, run_id=run_id).read_all()
    if not records or any(record["run_id"] != run_id for record in records):
        raise IntegrityError("Checkpointed ledger is empty or contains a different run identity.")
    run_created = [
        record
        for record in records
        if record["sequence"] == 0 and record["event_type"] == "RUN_CREATED"
    ]
    if len(run_created) != 1:
        raise IntegrityError("Checkpointed ledger lacks its unique initial RUN_CREATED event.")
    payload = run_created[0]["payload"]
    if not isinstance(payload, dict):
        raise IntegrityError("Checkpointed RUN_CREATED payload is not an object.")
    return report.entries, str(report.last_hash)


def verify_ledger_checkpoint(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    ledger_bytes: bytes,
    expected_suite_id: str,
    expected_case_id: str,
    expected_variant: str,
    expected_run_id: str,
    expected_target_snapshot_hash: str,
    expected_protocol_hash: str,
    now: datetime | str | None = None,
) -> VerifiedStatement:
    verified, _ = _verify(
        envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        now=now,
        predicate_name="ledger-checkpoint",
        predicate_schema="ledger-checkpoint-predicate",
        subject_bytes=ledger_bytes,
    )
    predicate = verified.predicate
    expected = {
        "suite_id": expected_suite_id,
        "case_id": expected_case_id,
        "variant": expected_variant,
        "run_id": expected_run_id,
        "target_snapshot_hash": expected_target_snapshot_hash,
        "protocol_hash": expected_protocol_hash,
        "ledger_sha256": _digest(ledger_bytes, "ledger_bytes"),
    }
    for field, value in expected.items():
        _expect_equal(predicate[field], value, field)
    entries, head = _verify_ledger_bytes(ledger_bytes, run_id=expected_run_id)
    _expect_equal(predicate["entry_count"], entries, "entry_count")
    _expect_equal(predicate["head_event_hash"], head, "head_event_hash")
    with tempfile.TemporaryDirectory(prefix="unasked-ledger-bind-") as directory:
        path = Path(directory) / "events.jsonl"
        path.write_bytes(ledger_bytes)
        initial_payload = EventLedger(path, run_id=expected_run_id).read_all()[0]["payload"]
    _expect_equal(
        initial_payload.get("target_snapshot_hash"),
        expected_target_snapshot_hash,
        "RUN_CREATED.target_snapshot_hash",
    )
    _expect_equal(
        initial_payload.get("protocol_hash"),
        expected_protocol_hash,
        "RUN_CREATED.protocol_hash",
    )
    return verified


def verify_trial_evaluation(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    custody_envelope_bytes: bytes,
    report_bytes: bytes,
    evidence_index_bytes: bytes,
    audit_bytes: bytes,
    run_matrix_bytes: bytes,
    expected_suite_id: str,
    expected_manifest_sha256: str,
    expected_protocol_hash: str,
    expected_run_bindings: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    now: datetime | str | None = None,
) -> VerifiedStatement:
    verified, _ = _verify(
        envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        now=now,
        predicate_name="trial-evaluation",
        predicate_schema="trial-evaluation-predicate",
        subject_bytes=report_bytes,
    )
    predicate = verified.predicate
    expected = {
        "suite_id": expected_suite_id,
        "manifest_sha256": expected_manifest_sha256,
        "protocol_hash": expected_protocol_hash,
        "custody_envelope_sha256": _digest(custody_envelope_bytes, "custody_envelope_bytes"),
        "report_sha256": _digest(report_bytes, "report_bytes"),
        "evidence_index_sha256": _digest(evidence_index_bytes, "evidence_index_bytes"),
        "audit_sha256": _digest(audit_bytes, "audit_bytes"),
        "run_matrix_sha256": _digest(run_matrix_bytes, "run_matrix_bytes"),
        "run_count": 35,
        "variant_count": 5,
        "case_count": 7,
    }
    for field, value in expected.items():
        _expect_equal(predicate[field], value, field)
    if not isinstance(expected_run_bindings, (tuple, list)):
        raise UsageError("expected_run_bindings must be a sequence of exact binding objects.")
    _expect_equal(predicate["run_bindings"], list(expected_run_bindings), "run_bindings")
    return verified


def verify_m0_certification(
    envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    manifest_bytes: bytes,
    custody_envelope_bytes: bytes,
    trial_evaluation_envelope_bytes: bytes,
    report_bytes: bytes,
    evidence_index_bytes: bytes,
    audit_bytes: bytes,
    run_matrix_bytes: bytes,
    expected_suite_id: str,
    expected_manifest_sha256: str,
    expected_protocol_hash: str,
    expected_run_bindings: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    now: datetime | str | None = None,
) -> CertificationVerification:
    verified, policy = _verify(
        envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        now=now,
        predicate_name="m0-certification",
        predicate_schema="m0-certification-predicate",
        subject_bytes=trial_evaluation_envelope_bytes,
    )
    predicate = verified.predicate
    expected = {
        "suite_id": expected_suite_id,
        "manifest_sha256": expected_manifest_sha256,
        "protocol_hash": expected_protocol_hash,
        "custody_envelope_sha256": _digest(custody_envelope_bytes, "custody_envelope_bytes"),
        "trial_evaluation_envelope_sha256": _digest(
            trial_evaluation_envelope_bytes, "trial_evaluation_envelope_bytes"
        ),
        "evidence_index_sha256": _digest(evidence_index_bytes, "evidence_index_bytes"),
        "audit_sha256": _digest(audit_bytes, "audit_bytes"),
        "run_matrix_sha256": _digest(run_matrix_bytes, "run_matrix_bytes"),
    }
    for field, value in expected.items():
        _expect_equal(predicate[field], value, field)

    reverified_custody = verify_custody_attestation(
        custody_envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        manifest_bytes=manifest_bytes,
        expected_suite_id=expected_suite_id,
        expected_manifest_sha256=expected_manifest_sha256,
        now=now,
    )
    reverified_evaluation = verify_trial_evaluation(
        trial_evaluation_envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        custody_envelope_bytes=custody_envelope_bytes,
        report_bytes=report_bytes,
        evidence_index_bytes=evidence_index_bytes,
        audit_bytes=audit_bytes,
        run_matrix_bytes=run_matrix_bytes,
        expected_suite_id=expected_suite_id,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_protocol_hash=expected_protocol_hash,
        expected_run_bindings=expected_run_bindings,
        now=now,
    )
    input_policy_hashes = {
        reverified_custody.predicate.get("trust_policy_sha256"),
        reverified_evaluation.predicate.get("trust_policy_sha256"),
    }
    inputs_valid = (
        input_policy_hashes == {policy.sha256}
        and reverified_custody.production_qualified
        and reverified_evaluation.production_qualified
        and reverified_custody.predicate.get("suite_id") == expected_suite_id
        and reverified_evaluation.predicate.get("suite_id") == expected_suite_id
        and reverified_custody.predicate.get("manifest_sha256") == expected_manifest_sha256
        and reverified_evaluation.predicate.get("manifest_sha256") == expected_manifest_sha256
        and reverified_evaluation.predicate.get("protocol_hash") == expected_protocol_hash
    )
    claims_demonstrated = predicate["decision"] == "M0_DEMONSTRATED"
    demonstrated = (
        policy.mode == "PRODUCTION"
        and verified.production_qualified
        and inputs_valid
        and claims_demonstrated
    )
    if claims_demonstrated and not demonstrated:
        raise IntegrityError(
            "Signed M0_DEMONSTRATED claim lacks complete production-qualified inputs."
        )
    reason = "M0_DEMONSTRATED" if demonstrated else "M0_NOT_DEMONSTRATED"
    return CertificationVerification(verified, demonstrated, reason)


__all__ = [
    "CertificationVerification",
    "read_exact_bytes",
    "verify_custody_attestation",
    "verify_isolation_attestation",
    "verify_ledger_checkpoint",
    "verify_m0_certification",
    "verify_trial_evaluation",
]
