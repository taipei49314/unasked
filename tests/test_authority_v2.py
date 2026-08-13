from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_attestations import MANIFEST, NOW, _common, _custody_predicate, _envelope, _policy
from test_integration import _prepared_candidate

from unasked.authority import AuthorityKernel, PreparedAuthorization
from unasked.budget import DEFAULT_M0_BUDGET
from unasked.errors import ConcurrentModificationError
from unasked.policy import Actor, State
from unasked.project import Project
from unasked.protocol import load_protocol, protocol_hash
from unasked.util import sha256_bytes

AUTHORITY_TYPE = "https://schemas.unasked.dev/attestations/authority-authorization/v0.4"
CHECKPOINT_TYPE = "https://schemas.unasked.dev/attestations/ledger-checkpoint/v0.4"
CUSTODY_TYPE = "https://schemas.unasked.dev/attestations/custody/v0.4"
ISOLATION_TYPE = "https://schemas.unasked.dev/attestations/isolation/v0.4"


@dataclass(frozen=True)
class AuthorizationCase:
    kernel: AuthorityKernel
    run_id: str
    candidate_id: str
    authority: Actor
    prepared: PreparedAuthorization
    inputs: dict[str, object]


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AuthorizationCase:
    original_create_run = Project.create_run

    def create_trial_run(
        project: Project,
        repository: str | Path,
        *,
        commit: str,
        actor: Actor,
        **kwargs: object,
    ) -> dict:
        preregistration = {
            "schema_version": "0.1.0",
            "record_type": "M0_TRIAL_PREREGISTRATION",
            "registration_id": "registration-authority-v2",
            "suite_id": "suite-1",
            "case_id": "case-1",
            "variant": "full-evidence-gated-system",
            "registered_at": "2026-08-01T00:00:00Z",
            "manifest_hash": sha256_bytes(MANIFEST),
            "protocol_hash": protocol_hash(load_protocol()),
            "budget_policy_hash": DEFAULT_M0_BUDGET.sha256,
            "target_commit": commit,
            "model": {"provider": "none", "name": "not-configured"},
        }
        return original_create_run(
            project,
            repository,
            commit=commit,
            actor=actor,
            trial_preregistration=preregistration,
            budget_policy=DEFAULT_M0_BUDGET,
            **kwargs,
        )

    monkeypatch.setattr(Project, "create_run", create_trial_run)
    project, service, run_id, candidate_id, _ = _prepared_candidate(tmp_path)
    service.replay(
        run_id,
        candidate_id,
        actor=Actor("reproducer-1", "independent_reproducer"),
        allowed_executables=[sys.executable],
    )
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED

    policy_bytes, policy_sha256, keys = _policy()
    run = project.get_run(run_id)
    target = project.get_target(run_id)
    binding = run["trial_binding"]
    custody_envelope = _envelope(
        CUSTODY_TYPE,
        _custody_predicate(policy_sha256),
        MANIFEST,
        keys["CUSTODIAN"],
    )
    replay_path = project.candidate_dir(run_id, candidate_id) / "replay" / "result.json"
    isolation_result = replay_path.read_bytes()
    isolation_envelope = _envelope(
        ISOLATION_TYPE,
        {
            **_common(policy_sha256, "actor-3"),
            "suite_id": binding["suite_id"],
            "case_id": binding["case_id"],
            "variant": binding["variant"],
            "run_id": run_id,
            "started_at": "2026-08-13T06:00:00Z",
            "completed_at": "2026-08-13T07:00:00Z",
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "executor_actor_id": "reproducer-1",
            "isolation_class": "EXTERNAL_SEALED",
            "network_mode": "DENY_ALL",
            "filesystem_mode": "IMMUTABLE_INPUT_ISOLATED_OUTPUT",
            "input_manifest_sha256": "a" * 64,
            "command_records_sha256": "b" * 64,
            "output_manifest_sha256": "c" * 64,
            "residual_state_detected": False,
        },
        isolation_result,
        keys["ISOLATION_ATTESTER"],
    )
    ledger_bytes = project.paths(run_id).ledger.read_bytes()
    ledger_report = project.ledger(run_id).verify(raise_on_error=True)
    checkpoint_envelope = _envelope(
        CHECKPOINT_TYPE,
        {
            **_common(policy_sha256, "actor-4"),
            "suite_id": binding["suite_id"],
            "case_id": binding["case_id"],
            "variant": binding["variant"],
            "run_id": run_id,
            "entry_count": ledger_report.entries,
            "head_event_hash": ledger_report.last_hash,
            "ledger_sha256": sha256_bytes(ledger_bytes),
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "checkpointed_at": "2026-08-13T07:00:00Z",
        },
        ledger_bytes,
        keys["LEDGER_WITNESS"],
    )
    kernel = AuthorityKernel(project)
    request = kernel.build_authorization_request(
        run_id,
        candidate_id,
        trust_policy_sha256=policy_sha256,
        checkpoint_envelope_sha256=sha256_bytes(checkpoint_envelope),
        custody_envelope_sha256=sha256_bytes(custody_envelope),
        isolation_envelope_sha256=sha256_bytes(isolation_envelope),
        generated_at=NOW,
    )
    authority = Actor("actor-1", "human_judge")
    authority_envelope = _envelope(
        AUTHORITY_TYPE,
        {
            **_common(policy_sha256, "actor-1"),
            "run_id": run_id,
            "candidate_id": candidate_id,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "context_manifest_hash": run["context_manifest_hash"],
            "evidence_bundle_hash": request.evidence_bundle_hash,
            "ledger_checkpoint_envelope_sha256": sha256_bytes(checkpoint_envelope),
            "custody_envelope_sha256": sha256_bytes(custody_envelope),
            "isolation_envelope_sha256": sha256_bytes(isolation_envelope),
            "prepared_graph_sha256": request.prepared_graph_sha256,
            "decision": "AUTHORIZE_VERIFIED",
            "authorized_state": "VERIFIED",
            "expires_at": "2026-08-20T00:00:00Z",
        },
        request.prepared_graph_bytes,
        keys["DISCOVERY_AUTHORITY"],
    )
    inputs: dict[str, object] = {
        "authority": authority,
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
    prepared = kernel.prepare_authorization(run_id, candidate_id, **inputs)
    return AuthorizationCase(kernel, run_id, candidate_id, authority, prepared, inputs)


def test_authority_v2_happy_path_commits_and_reauthenticates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)

    result = case.kernel.commit_authorization(case.prepared, **case.inputs)

    assert result["authorization_commit"]["prepared_graph_sha256"] == (
        case.prepared.request.prepared_graph_sha256
    )
    assert result["authorization_commit"]["evidence_bundle_hash"] == (
        case.prepared.request.evidence_bundle_hash
    )
    assert result["verdict"]["evidence_bundle_hash"] == case.prepared.request.evidence_bundle_hash
    assert result["certificate"]["evidence_bundle_hash"] == (
        case.prepared.request.evidence_bundle_hash
    )
    assert case.kernel.project.current_state(case.run_id, case.candidate_id) is State.VERIFIED
    audit = case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)
    assert audit["valid"] is True


def test_authority_v2_marker_remains_valid_after_later_ledger_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)

    case.kernel.project.append_event(case.run_id, "POST_AUTHORIZATION_AUDIT", {"ok": True})

    audit = case.kernel.audit_certificate_v2(case.run_id, case.candidate_id, **case.inputs)
    assert audit["valid"] is True


def test_authority_v2_detects_drift_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.project.ledger(case.run_id).append("TEST_DRIFT", {"reason": "race"})

    with pytest.raises(ConcurrentModificationError):
        case.kernel.commit_authorization(case.prepared, **case.inputs)

    assert case.kernel.project.current_state(case.run_id, case.candidate_id) is State.REPRODUCED


def test_v2_certificate_without_commit_marker_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    case.kernel.commit_authorization(case.prepared, **case.inputs)
    marker = (
        case.kernel.project.candidate_dir(case.run_id, case.candidate_id)
        / "authorization-commit.json"
    )
    marker.unlink()

    audit = case.kernel.audit_certificate(case.run_id, case.candidate_id)

    assert audit["valid"] is False
    assert audit["checks"]["authorization_v2_marker_bound"] is False
