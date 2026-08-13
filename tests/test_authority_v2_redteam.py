from __future__ import annotations

import base64
import json
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest
from test_attestations import MANIFEST, NOW, _envelope, _policy
from test_authority_v2 import (
    AUTHORITY_TYPE,
    CHECKPOINT_TYPE,
    CUSTODY_TYPE,
    ISOLATION_TYPE,
    AuthorizationCase,
    _case,
)
from test_integration import _prepared_candidate

from unasked.authority import AuthorityKernel
from unasked.errors import (
    ConcurrentModificationError,
    IntegrityError,
    PolicyError,
    UnaskedError,
)
from unasked.policy import Actor, State
from unasked.records import append_jsonl
from unasked.util import canonical_json, read_json, sha256_bytes


def _payload(envelope_bytes: bytes) -> dict:
    envelope = json.loads(envelope_bytes)
    return json.loads(base64.b64decode(envelope["payload"]))


def _transport_variant(envelope_bytes: bytes) -> bytes:
    envelope = json.loads(envelope_bytes)
    envelope["ignored_transport_field"] = {"must_not_change_identity": True}
    return canonical_json(envelope)


def _file_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _assert_no_authoritative_outputs(case: AuthorizationCase) -> None:
    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    assert case.kernel.project.current_state(case.run_id, case.candidate_id) is State.REPRODUCED
    assert not (root / "verdict.json").exists()
    assert not (root / "certificate.yaml").exists()
    assert not (root / "authorization-commit.json").exists()


def _assert_audits_reject(case: AuthorizationCase) -> None:
    audit = case.kernel.audit_certificate(case.run_id, case.candidate_id)
    assert audit["valid"] is False
    with pytest.raises(UnaskedError):
        case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)


def _resigned_inputs(
    case: AuthorizationCase,
    *,
    mutate_policy: Callable[[dict], None] | None = None,
    role_actor_overrides: dict[str, str] | None = None,
    authority_predicate_updates: dict[str, object] | None = None,
    isolation_predicate_updates: dict[str, object] | None = None,
) -> tuple[dict[str, object], object]:
    """Reissue a complete chain after an intentional policy/predicate mutation."""

    policy = json.loads(case.inputs["trust_policy_bytes"])
    for key in policy["keys"]:
        replacement = (role_actor_overrides or {}).get(key["role"])
        if replacement is not None:
            key["actor_id"] = replacement
    if mutate_policy is not None:
        mutate_policy(policy)
    policy_bytes = canonical_json(policy)
    policy_sha256 = sha256_bytes(policy_bytes)
    _, _, private_keys = _policy()
    actor_by_role = {key["role"]: key["actor_id"] for key in policy["keys"]}

    custody_predicate = deepcopy(_payload(case.inputs["custody_envelope_bytes"])["predicate"])
    custody_predicate.update(
        trust_policy_sha256=policy_sha256,
        issuer_actor_id=actor_by_role["CUSTODIAN"],
    )
    custody_envelope = _envelope(
        CUSTODY_TYPE,
        custody_predicate,
        MANIFEST,
        private_keys["CUSTODIAN"],
    )

    isolation_result = case.inputs["isolation_result_bytes"]
    isolation_predicate = deepcopy(_payload(case.inputs["isolation_envelope_bytes"])["predicate"])
    isolation_predicate.update(
        trust_policy_sha256=policy_sha256,
        issuer_actor_id=actor_by_role["ISOLATION_ATTESTER"],
    )
    isolation_predicate.update(isolation_predicate_updates or {})
    isolation_envelope = _envelope(
        ISOLATION_TYPE,
        isolation_predicate,
        isolation_result,
        private_keys["ISOLATION_ATTESTER"],
    )

    ledger_bytes = case.kernel.project.paths(case.run_id).ledger.read_bytes()
    checkpoint_predicate = deepcopy(_payload(case.inputs["checkpoint_envelope_bytes"])["predicate"])
    checkpoint_predicate.update(
        trust_policy_sha256=policy_sha256,
        issuer_actor_id=actor_by_role["LEDGER_WITNESS"],
    )
    checkpoint_envelope = _envelope(
        CHECKPOINT_TYPE,
        checkpoint_predicate,
        ledger_bytes,
        private_keys["LEDGER_WITNESS"],
    )

    request = case.kernel.build_authorization_request(
        case.run_id,
        case.candidate_id,
        trust_policy_sha256=policy_sha256,
        checkpoint_envelope_sha256=sha256_bytes(checkpoint_envelope),
        custody_envelope_sha256=sha256_bytes(custody_envelope),
        isolation_envelope_sha256=sha256_bytes(isolation_envelope),
        generated_at=NOW,
    )
    authority_predicate = deepcopy(_payload(case.inputs["authority_envelope_bytes"])["predicate"])
    authority_predicate.update(
        trust_policy_sha256=policy_sha256,
        issuer_actor_id=actor_by_role["DISCOVERY_AUTHORITY"],
        evidence_bundle_hash=request.evidence_bundle_hash,
        ledger_checkpoint_envelope_sha256=sha256_bytes(checkpoint_envelope),
        custody_envelope_sha256=sha256_bytes(custody_envelope),
        isolation_envelope_sha256=sha256_bytes(isolation_envelope),
        prepared_graph_sha256=request.prepared_graph_sha256,
    )
    authority_predicate.update(authority_predicate_updates or {})
    authority_envelope = _envelope(
        AUTHORITY_TYPE,
        authority_predicate,
        request.prepared_graph_bytes,
        private_keys["DISCOVERY_AUTHORITY"],
    )
    inputs: dict[str, object] = {
        "authority": Actor(actor_by_role["DISCOVERY_AUTHORITY"], "human_judge"),
        "authority_envelope_bytes": authority_envelope,
        "checkpoint_envelope_bytes": checkpoint_envelope,
        "custody_envelope_bytes": custody_envelope,
        "isolation_envelope_bytes": isolation_envelope,
        "trust_policy_bytes": policy_bytes,
        "trust_policy_sha256": policy_sha256,
        "manifest_bytes": MANIFEST,
        "isolation_result_bytes": isolation_result,
        "now": NOW,
    }
    return inputs, request


def test_signing_request_is_stable_and_contains_no_clock_or_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    request = case.prepared.request
    inputs = {
        "trust_policy_sha256": request.trust_policy_sha256,
        "checkpoint_envelope_sha256": request.checkpoint_envelope_sha256,
        "custody_envelope_sha256": request.custody_envelope_sha256,
        "isolation_envelope_sha256": request.isolation_envelope_sha256,
    }
    first = case.kernel.build_authorization_request(
        case.run_id,
        case.candidate_id,
        **inputs,
        generated_at="2026-08-13T08:00:00Z",
    )
    second = case.kernel.build_authorization_request(
        case.run_id,
        case.candidate_id,
        **inputs,
        generated_at="2099-12-31T23:59:59Z",
    )

    assert first.prepared_graph_bytes == second.prepared_graph_bytes
    assert first.prepared_graph_sha256 == second.prepared_graph_sha256
    assert first.signing_request() == second.signing_request()
    assert "generated_at" not in first.signing_request()
    encoded = canonical_json(first.signing_request()).decode()
    assert str(case.kernel.project.root.resolve()) not in encoded
    assert str(tmp_path.resolve()) not in encoded


def test_prepare_is_a_zero_write_operation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = _case(tmp_path, monkeypatch)
    before = _file_snapshot(case.kernel.project.root)

    rebuilt = case.kernel.prepare_authorization(case.run_id, case.candidate_id, **case.inputs)

    assert rebuilt.request.stable_dict() == case.prepared.request.stable_dict()
    assert _file_snapshot(case.kernel.project.root) == before
    _assert_no_authoritative_outputs(case)


def test_prepare_rejects_wrong_graph_subject_and_every_signed_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    _, _, private_keys = _policy()
    predicate = _payload(case.inputs["authority_envelope_bytes"])["predicate"]
    wrong_subject = _envelope(
        AUTHORITY_TYPE,
        predicate,
        b'{"different":"authorization-graph"}',
        private_keys["DISCOVERY_AUTHORITY"],
    )
    with pytest.raises(IntegrityError):
        case.kernel.prepare_authorization(
            case.run_id,
            case.candidate_id,
            **{**case.inputs, "authority_envelope_bytes": wrong_subject},
        )

    wrong_values: dict[str, object] = {
        "run_id": "run-substituted",
        "candidate_id": "candidate-substituted",
        "target_snapshot_hash": "d" * 64,
        "protocol_hash": "d" * 64,
        "knowledge_boundary_hash": "d" * 64,
        "context_manifest_hash": "d" * 64,
        "evidence_bundle_hash": "d" * 64,
        "ledger_checkpoint_envelope_sha256": "d" * 64,
        "custody_envelope_sha256": "d" * 64,
        "isolation_envelope_sha256": "d" * 64,
        "prepared_graph_sha256": "d" * 64,
        "trust_policy_sha256": "d" * 64,
        "issuer_actor_id": "actor-substituted",
    }
    for field_name, wrong_value in wrong_values.items():
        changed = {**predicate, field_name: wrong_value}
        envelope = _envelope(
            AUTHORITY_TYPE,
            changed,
            case.prepared.request.prepared_graph_bytes,
            private_keys["DISCOVERY_AUTHORITY"],
        )
        with pytest.raises(UnaskedError):
            case.kernel.prepare_authorization(
                case.run_id,
                case.candidate_id,
                **{**case.inputs, "authority_envelope_bytes": envelope},
            )


def test_prepare_rejects_wrong_authority_role_type_expiry_and_policy_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    _, _, private_keys = _policy()
    predicate = _payload(case.inputs["authority_envelope_bytes"])["predicate"]
    attacks = [
        _envelope(
            AUTHORITY_TYPE,
            predicate,
            case.prepared.request.prepared_graph_bytes,
            private_keys["CUSTODIAN"],
        ),
        _envelope(
            CUSTODY_TYPE,
            predicate,
            case.prepared.request.prepared_graph_bytes,
            private_keys["DISCOVERY_AUTHORITY"],
        ),
        _envelope(
            AUTHORITY_TYPE,
            {**predicate, "expires_at": "2026-08-13T07:59:59Z"},
            case.prepared.request.prepared_graph_bytes,
            private_keys["DISCOVERY_AUTHORITY"],
        ),
    ]
    for envelope in attacks:
        with pytest.raises(UnaskedError):
            case.kernel.prepare_authorization(
                case.run_id,
                case.candidate_id,
                **{**case.inputs, "authority_envelope_bytes": envelope},
            )

    whitespace_policy = case.inputs["trust_policy_bytes"] + b"\n"
    with pytest.raises(IntegrityError):
        case.kernel.prepare_authorization(
            case.run_id,
            case.candidate_id,
            **{**case.inputs, "trust_policy_bytes": whitespace_policy},
        )


@pytest.mark.parametrize(
    ("role", "producer_actor"),
    [
        ("CUSTODIAN", "explorer-1"),
        ("ISOLATION_ATTESTER", "reproducer-1"),
        ("LEDGER_WITNESS", "reviewer-1"),
        ("DISCOVERY_AUTHORITY", "executor-1"),
    ],
)
def test_prepare_rejects_external_self_signing_and_actor_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    producer_actor: str,
) -> None:
    case = _case(tmp_path, monkeypatch)
    inputs, _ = _resigned_inputs(
        case,
        role_actor_overrides={role: producer_actor},
    )

    with pytest.raises(PolicyError, match="separated"):
        case.kernel.prepare_authorization(case.run_id, case.candidate_id, **inputs)
    _assert_no_authoritative_outputs(case)


def test_prepare_rejects_isolation_claim_for_a_different_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    inputs, _ = _resigned_inputs(
        case,
        isolation_predicate_updates={"executor_actor_id": "executor-1"},
    )

    with pytest.raises(IntegrityError, match="executor"):
        case.kernel.prepare_authorization(case.run_id, case.candidate_id, **inputs)


@pytest.mark.parametrize("attack", ["revoked", "not-yet-valid", "expired"])
def test_prepare_rejects_non_active_or_out_of_window_authority_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    case = _case(tmp_path, monkeypatch)

    def invalidate_authority(policy: dict) -> None:
        key = next(key for key in policy["keys"] if key["role"] == "DISCOVERY_AUTHORITY")
        if attack == "revoked":
            key["status"] = "REVOKED"
        elif attack == "not-yet-valid":
            key["valid_from"] = "2026-08-13T07:30:00Z"
        else:
            key["valid_until"] = "2026-08-13T06:30:00Z"

    inputs, _ = _resigned_inputs(case, mutate_policy=invalidate_authority)
    with pytest.raises(UnaskedError):
        case.kernel.prepare_authorization(case.run_id, case.candidate_id, **inputs)


def test_authorization_graph_rejects_symlinked_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    candidate_path = (
        case.kernel.project.candidate_dir(case.run_id, case.candidate_id) / "candidate.json"
    )
    outside = tmp_path / "outside-candidate.json"
    outside.write_bytes(candidate_path.read_bytes())
    candidate_path.unlink()
    try:
        candidate_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"This Windows host cannot create a test symlink: {exc}")

    with pytest.raises(IntegrityError, match="symlink|reparse"):
        case.kernel.build_authorization_request(
            case.run_id,
            case.candidate_id,
            trust_policy_sha256=case.prepared.request.trust_policy_sha256,
            checkpoint_envelope_sha256=case.prepared.request.checkpoint_envelope_sha256,
            custody_envelope_sha256=case.prepared.request.custody_envelope_sha256,
            isolation_envelope_sha256=case.prepared.request.isolation_envelope_sha256,
        )


def test_legacy_v03_path_cannot_claim_authenticated_authorization(
    tmp_path: Path,
) -> None:
    project, service, run_id, candidate_id, _ = _prepared_candidate(tmp_path)
    service.replay(
        run_id,
        candidate_id,
        actor=Actor("reproducer-1", "independent_reproducer"),
        allowed_executables=[sys.executable],
    )
    authority = Actor("authority-legacy", "human_judge")

    with pytest.raises(PolicyError):
        AuthorityKernel(project).authorize(
            run_id,
            candidate_id,
            authority=authority,
        )
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED


def test_audit_rejects_exact_byte_substitution_of_each_external_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)

    for field_name in (
        "authority_envelope_bytes",
        "checkpoint_envelope_bytes",
        "custody_envelope_bytes",
        "isolation_envelope_bytes",
    ):
        substituted = {**case.inputs, field_name: _transport_variant(case.inputs[field_name])}
        with pytest.raises(IntegrityError, match="Retained external attestation"):
            case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **substituted)


def test_base_and_v2_audits_reject_marker_field_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)
    marker_path = (
        case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
        / "authorization-commit.json"
    )
    marker = read_json(marker_path)
    marker["evidence_bundle_hash"] = "d" * 64
    marker_path.write_bytes(canonical_json(marker) + b"\n")

    _assert_audits_reject(case)


@pytest.mark.parametrize("cas_field", ["prepared_graph_artifact_sha256", "evidence_bundle_hash"])
def test_base_and_v2_audits_reject_tampered_graph_or_bundle_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cas_field: str,
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)
    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    digest = read_json(root / "authorization-commit.json")[cas_field]
    case.kernel.store.path_for(digest).write_bytes(b'{"tampered":true}')

    _assert_audits_reject(case)


def test_base_and_v2_audits_reject_tampered_c_pre_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)
    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    digest = read_json(root / "authorization-commit.json")["c_pre"]["sha256"]
    case.kernel.store.path_for(digest).write_bytes(b'{"tampered":"ledger"}\n')

    _assert_audits_reject(case)


def test_marker_must_be_unique_and_exactly_adjacent_but_need_not_remain_ledger_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)

    case.kernel.project.append_event(case.run_id, "LEGAL_C_FINAL", {"phase": "post-authorization"})
    assert case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)["valid"]

    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    marker_path = root / "authorization-commit.json"
    case.kernel.project.append_event(
        case.run_id,
        "AUTHORIZATION_COMMITTED",
        {
            "candidate_id": case.candidate_id,
            "path": "authorization-commit.json",
            "sha256": sha256_bytes(marker_path.read_bytes()),
        },
    )
    _assert_audits_reject(case)


@pytest.mark.parametrize(
    "drift",
    [
        "evidence",
        "ledger",
        "state",
        "authority-envelope",
        "checkpoint-envelope",
        "custody-envelope",
        "isolation-envelope",
    ],
)
def test_commit_rejects_every_prepared_graph_or_envelope_drift_as_concurrent_modification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    case = _case(tmp_path, monkeypatch)
    inputs = dict(case.inputs)
    if drift == "evidence":
        path = case.kernel.project.candidate_dir(case.run_id, case.candidate_id) / "novelty.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif drift == "ledger":
        case.kernel.project.append_event(case.run_id, "CONCURRENT_DRIFT", {"kind": "ledger"})
    elif drift == "state":
        append_jsonl(
            case.kernel.project.candidate_dir(case.run_id, case.candidate_id) / "states.jsonl",
            {
                "candidate_id": case.candidate_id,
                "occurred_at": NOW,
                "from": "REPRODUCED",
                "to": "SUPPORTED",
                "actor": Actor("attacker", "explorer").to_dict(),
                "reason": "Simulated concurrent state drift.",
            },
        )
    else:
        field_name = drift.replace("-", "_") + "_bytes"
        inputs[field_name] = _transport_variant(inputs[field_name])

    with pytest.raises(ConcurrentModificationError):
        case.kernel.commit_authorization(case.prepared, **inputs)
    if drift == "state":
        root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
        assert case.kernel.project.current_state(case.run_id, case.candidate_id) is State.SUPPORTED
        assert not (root / "verdict.json").exists()
        assert not (root / "certificate.yaml").exists()
        assert not (root / "authorization-commit.json").exists()
    else:
        _assert_no_authoritative_outputs(case)


def test_policy_exact_byte_drift_fails_closed_without_authoritative_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    inputs = {**case.inputs, "trust_policy_bytes": case.inputs["trust_policy_bytes"] + b"\n"}

    with pytest.raises(IntegrityError):
        case.kernel.commit_authorization(case.prepared, **inputs)
    _assert_no_authoritative_outputs(case)


def test_parallel_commit_serializes_to_exactly_one_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)

    def commit() -> str:
        try:
            case.kernel.commit_authorization(case.prepared, **case.inputs)
        except ConcurrentModificationError:
            return "concurrent"
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: commit(), range(2)))

    assert outcomes == ["committed", "concurrent"]
    assert case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)["valid"]


def test_missing_retained_external_envelope_cas_invalidates_base_and_v2_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)
    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    digest = read_json(root / "authorization-commit.json")["authority_envelope_sha256"]
    case.kernel.store.path_for(digest).unlink()

    _assert_audits_reject(case)


def test_partial_marker_write_crash_never_produces_an_authoritative_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    original_write = case.kernel.project.write_candidate_artifact

    def crash_on_marker(*args: object, **kwargs: object) -> dict:
        if len(args) >= 3 and args[2] == "authorization-commit.json":
            raise OSError("simulated marker persistence crash")
        return original_write(*args, **kwargs)

    monkeypatch.setattr(case.kernel.project, "write_candidate_artifact", crash_on_marker)
    with pytest.raises(OSError, match="marker persistence"):
        case.kernel.commit_authorization(case.prepared, **case.inputs)

    root = case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
    assert not (root / "authorization-commit.json").exists()
    assert case.kernel.audit_certificate(case.run_id, case.candidate_id)["valid"] is False
    with pytest.raises(UnaskedError):
        case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)
