from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from unasked.authority import AuthorityKernel
from unasked.cli import main
from unasked.errors import PolicyError
from unasked.policy import Actor, State
from unasked.project import Project
from unasked.util import canonical_json, hash_json, read_json, sha256_bytes, utc_now
from unasked.workflow import InvestigationService


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "README.md").write_text(
        "# Fixture\n\nThe documented command prints expected.\n", encoding="utf-8"
    )
    (repository / "tool.py").write_text("print('actual')\n", encoding="utf-8")
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "fixture@example.invalid")
    _git(repository, "config", "user.name", "Fixture")
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


def _prepared_candidate(
    tmp_path: Path,
    *,
    capture_bytes: int = 0,
    disk_bytes: int = 10_000_000,
    expected_status: str = "SUCCEEDED",
) -> tuple[Project, InvestigationService, str, str, str]:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    service = InvestigationService(project)
    explorer = Actor("explorer-1", "explorer")
    run = project.create_run(repository, commit=commit, actor=explorer)
    run_id = run["run_id"]
    service.observe(run_id, actor=explorer)
    claim = next(
        record
        for record in project.records(run_id, "observations")
        if record["kind"] == "CLAIM" and "prints expected" in record["statement"]
    )
    expectation = service.add_expectation(
        run_id,
        actor=explorer,
        expectation_type="explicit",
        statement="The documented command prints expected.",
        reasoning_chain=["README line is an explicit user-facing behavior claim."],
        source_observation_ids=[claim["observation_id"]],
        strength="strong",
    )
    candidate_bundle = service.propose_candidate(
        run_id,
        actor=explorer,
        expectation_ids=[expectation["expectation_id"]],
        observation_ids=[claim["observation_id"]],
        discrepancy="The planned runtime probe may print actual instead of expected.",
        materiality_question="Would this change release confidence in the documented CLI?",
        origin="model_explorer",
        main_hypothesis="The executable behavior contradicts the README claim.",
        benign_alternatives=["The README may describe a different invocation mode."],
        falsification_conditions=["The exact documented invocation prints expected."],
        minimal_experiment="Run a fixed Python command and capture exact output.",
        supporting_outcomes=["stdout is actual"],
        falsifying_outcomes=["stdout is expected"],
        inconclusive_outcomes=["the interpreter cannot start"],
        estimated_seconds=5,
        risk_level="low",
        risks=["local process execution inside the temporary worktree"],
    )
    candidate_id = candidate_bundle["candidate"]["candidate_id"]
    service.plan_experiment(
        run_id,
        candidate_id,
        actor=Actor("planner-1", "experiment_planner"),
        commands=[
            {
                "command_id": "CMD-PROBE",
                "argv": [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"Path('capture.bin').write_bytes(b'x' * {capture_bytes}); "
                        "print('actual')"
                        if capture_bytes
                        else "print('actual')"
                    ),
                ],
                "working_directory": ".",
                "purpose": "Probe one deterministic observable behavior.",
                "expected_observation": "stdout is exactly actual followed by newline.",
            }
        ],
        support_criteria=["CMD-PROBE stdout equals actual"],
        falsify_criteria=["CMD-PROBE stdout equals expected"],
        inconclusive_criteria=["CMD-PROBE cannot execute"],
        outcome_assertions=[
            {
                "assertion_id": "A-SUPPORT-STDOUT",
                "command_id": "CMD-PROBE",
                "field": "STDOUT_SHA256",
                "operator": "EQUALS",
                "expected": sha256_bytes(f"actual{os.linesep}".encode()),
                "classification": "SUPPORTS",
            },
            {
                "assertion_id": "A-FALSIFY-STDOUT",
                "command_id": "CMD-PROBE",
                "field": "STDOUT_SHA256",
                "operator": "EQUALS",
                "expected": sha256_bytes(f"expected{os.linesep}".encode()),
                "classification": "FALSIFIES",
            },
        ],
        wall_seconds=10,
        cpu_seconds=10,
        disk_bytes=disk_bytes,
        processes=4,
    )
    result = service.execute_experiment(
        run_id,
        candidate_id,
        actor=Actor("executor-1", "sandbox_executor"),
        allowed_executables=[sys.executable],
    )
    assert result["status"] == expected_status
    assert result["observed_outcome"] == "SUPPORTS"
    project.transition_candidate(
        run_id,
        candidate_id,
        State.SUPPORTED,
        actor=explorer,
        reason="Recorded stdout matches the predeclared supporting criterion.",
    )
    evidence_hash = result["evidence_refs"][0]["sha256"]
    challenge_types = (
        "BENIGN_ALTERNATIVE",
        "NEGATIVE_CONTROL",
        "SEMANTIC_VARIANT",
        "COMPLETENESS_CHECK",
    )
    challenge_attempts = []
    challenge_hashes = []
    for index, attempt_type in enumerate(challenge_types, start=1):
        predeclared = {
            "command": ["fixture-challenge", str(index)],
            "purpose": f"Exercise {attempt_type.lower()}.",
        }
        predeclared_hash = hash_json(predeclared)
        metadata = service.store.put_bytes(
            canonical_json(
                {
                    "schema_version": "0.1.0",
                    "attempt_id": f"CH-{index}",
                    "attempt_type": attempt_type,
                    "predeclared_input": predeclared,
                    "predeclared_input_hash": predeclared_hash,
                    "status": "EXECUTED",
                    "observed_outcome": "SURVIVED",
                    "execution": {
                        "exit_code": 0,
                        "stdout_sha256": evidence_hash,
                    },
                }
            ),
            media_type="application/json",
            original_name=f"challenge-{index}.json",
        )
        challenge_hashes.append(metadata.sha256)
        challenge_attempts.append(
            {
                "attempt_id": f"CH-{index}",
                "attempt_type": attempt_type,
                "description": f"Execute predeclared {attempt_type.lower()} challenge.",
                "predeclared_input_hash": predeclared_hash,
                "result_ref": metadata.to_reference(),
                "observed_outcome": "SURVIVED",
            }
        )
    service.add_review(
        run_id,
        candidate_id,
        actor=Actor("falsifier-1", "falsifier"),
        review_type="counterevidence",
        conclusion="pass",
        findings=["The alternative and controls did not explain the captured output."],
        evidence_hashes=challenge_hashes,
        tested_alternatives=["README describes another invocation mode"],
        negative_control="A fixed print of expected produced expected.",
        semantic_variant="The probe was repeated from a renamed worktree.",
        completeness_check="README and executable entrypoint were both inspected.",
        challenge_attempts=challenge_attempts,
    )
    judge = Actor("reviewer-1", "human_judge")
    service.add_review(
        run_id,
        candidate_id,
        actor=judge,
        review_type="novelty",
        conclusion="pass",
        findings=["The declared boundary does not state this discrepancy."],
        evidence_hashes=[evidence_hash],
    )
    service.add_review(
        run_id,
        candidate_id,
        actor=judge,
        review_type="known_issue",
        conclusion="pass",
        findings=["No known-issue snapshot states this discrepancy."],
        evidence_hashes=[evidence_hash],
    )
    service.add_review(
        run_id,
        candidate_id,
        actor=judge,
        review_type="materiality",
        conclusion="pass",
        findings=["The discrepancy changes release confidence."],
        evidence_hashes=[evidence_hash],
        decision_impact="Block the release until documentation or behavior is reconciled.",
    )
    service.record_custody_attestation(
        run_id,
        actor=Actor("custodian-1", "principal_investigator"),
        sealed_manifest_hash="a" * 64,
        access_log_hash="b" * 64,
        sealed_at="2000-01-01T00:00:00Z",
        external_store_reference="private://sealed-evaluation/fixture",
    )
    return project, service, run_id, candidate_id, evidence_hash


def test_local_replay_is_reproduced_but_not_authorized(tmp_path: Path) -> None:
    project, service, run_id, candidate_id, _ = _prepared_candidate(tmp_path)
    replay = service.replay(
        run_id,
        candidate_id,
        actor=Actor("reproducer-1", "independent_reproducer"),
        allowed_executables=[sys.executable],
    )
    assert replay["status"] == "PASS"
    replay_environment = read_json(
        project.candidate_dir(run_id, candidate_id) / "replay" / "environment.json"
    )
    assert replay_environment["input_manifest"]["allowed_executables"] == [sys.executable]
    assert replay_environment["input_manifest"]["system_commands"] == [
        {
            "command_id": "CMD-CAPTURE-DIFF",
            "argv": [
                "unasked-internal",
                "capture-worktree-mutations",
                "--format=canonical-json",
            ],
        }
    ]
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED

    authority = Actor("judge-2", "human_judge")
    report = AuthorityKernel(project).evaluate(run_id, candidate_id, authority=authority)
    assert report.eligible is False
    assert report.detailed_checks["clean_replay_passed"] is False
    with pytest.raises(PolicyError, match="not authorized"):
        AuthorityKernel(project).authorize(run_id, candidate_id, authority=authority)
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED


def test_matching_incomplete_captures_never_pass_replay(tmp_path: Path) -> None:
    project, service, run_id, candidate_id, _ = _prepared_candidate(
        tmp_path,
        capture_bytes=2,
        disk_bytes=1,
        expected_status="FAILED",
    )

    replay = service.replay(
        run_id,
        candidate_id,
        actor=Actor("reproducer-1", "independent_reproducer"),
        allowed_executables=[sys.executable],
    )

    assert replay["status"] == "FAIL"
    assert replay["core_result_match"] is False
    assert replay["clean_environment"] is False
    assert replay["residual_state_detected"] is True
    assert replay["independence_attestation"]["no_explorer_state"] is False
    assert replay["independence_attestation"]["no_unrecorded_files"] is False
    assert project.current_state(run_id, candidate_id) is State.SUPPORTED


def test_authority_requires_a_succeeded_experiment(tmp_path: Path) -> None:
    project, _, run_id, candidate_id, _ = _prepared_candidate(tmp_path)
    result_path = project.candidate_dir(run_id, candidate_id) / "experiment" / "result.json"
    result = read_json(result_path)
    result["status"] = "FAILED"
    result_path.write_bytes(canonical_json(result) + b"\n")

    report = AuthorityKernel(project).evaluate(
        run_id,
        candidate_id,
        authority=Actor("judge-2", "human_judge"),
    )

    assert report.detailed_checks["experiment_complete"] is False


def test_external_evidence_is_recorded_but_cannot_self_authorize(
    tmp_path: Path,
    capsys,
) -> None:
    project, service, run_id, candidate_id, evidence_hash = _prepared_candidate(tmp_path)
    bundle = project.read_candidate(run_id, candidate_id)
    experiment = read_json(
        project.candidate_dir(run_id, candidate_id) / "experiment" / "result.json"
    )
    replay_commands = [
        service.store.put_bytes(
            canonical_json(execution),
            media_type="application/json",
            original_name=f"external-replay-command-{index}.json",
        )
        for index, execution in enumerate(experiment["executions"], start=1)
    ]
    input_manifest = read_json(
        project.candidate_dir(run_id, candidate_id) / "experiment" / "environment.json"
    )["input_manifest"]
    reproducer = Actor("reproducer-1", "independent_reproducer")
    isolation_receipt = service.store.put_bytes(
        canonical_json(
            {
                "schema_version": "0.1.0",
                "issuer": "test-external-isolator",
                "claims": [
                    "NETWORK_ISOLATED",
                    "RESOURCE_LIMITS_ENFORCED",
                    "SECRET_FREE",
                ],
                "status": "ATTESTED",
                "subject": {
                    "run_id": run_id,
                    "source_run_id": run_id,
                    "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
                    "reproducer_actor_id": reproducer.actor_id,
                    "input_manifest_hash": hash_json(input_manifest),
                    "command_result_sha256s": [metadata.sha256 for metadata in replay_commands],
                },
            }
        ),
        media_type="application/json",
        original_name="external-isolation-receipt.json",
    )
    replay_result = {
        "schema_version": "0.1.0",
        "replay_id": f"RP-{candidate_id[2:]}",
        "run_id": run_id,
        "source_run_id": run_id,
        "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "status": "PASS",
        "clean_environment": True,
        "environment_hash": "0" * 64,
        "core_result_match": True,
        "residual_state_detected": False,
        "command_result_refs": [metadata.to_reference() for metadata in replay_commands],
        "evidence_hashes": [
            *(metadata.sha256 for metadata in replay_commands),
            isolation_receipt.sha256,
        ],
        "reproducer": reproducer.to_dict(),
        "independence_attestation": {
            "no_explorer_state": True,
            "no_unrecorded_files": True,
            "input_manifest_hash": hash_json(input_manifest),
        },
    }
    environment = {
        "adapter": "test-external-isolator",
        "fresh_git_worktree": True,
        "network_isolated": True,
        "secret_isolation": "enforced",
        "limits_enforced": {
            "wall_seconds": True,
            "cpu_seconds": True,
            "disk_bytes": True,
            "processes": True,
        },
        "input_manifest": input_manifest,
        "isolation_attestation": {
            "issuer": "test-external-isolator",
            "claims": [
                "NETWORK_ISOLATED",
                "RESOURCE_LIMITS_ENFORCED",
                "SECRET_FREE",
            ],
            "receipt_ref": isolation_receipt.to_reference(),
        },
    }
    result_path = tmp_path / "external-replay.json"
    environment_path = tmp_path / "external-environment.json"
    result_path.write_text(json.dumps(replay_result), encoding="utf-8")
    environment_path.write_text(json.dumps(environment), encoding="utf-8")
    with pytest.raises(PolicyError, match="environment_hash"):
        service.import_external_replay(
            run_id,
            candidate_id,
            actor=reproducer,
            result_path=result_path,
            environment_path=environment_path,
        )
    unrelated_receipt = service.store.put_bytes(
        b"unrelated",
        media_type="application/octet-stream",
        original_name="unrelated-receipt.bin",
    )
    unrelated_environment = {
        **environment,
        "isolation_attestation": {
            **environment["isolation_attestation"],
            "receipt_ref": unrelated_receipt.to_reference(),
        },
    }
    replay_result["environment_hash"] = hash_json(unrelated_environment)
    result_path.write_text(json.dumps(replay_result), encoding="utf-8")
    environment_path.write_text(json.dumps(unrelated_environment), encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid JSON evidence"):
        service.import_external_replay(
            run_id,
            candidate_id,
            actor=reproducer,
            result_path=result_path,
            environment_path=environment_path,
        )

    replay_result["environment_hash"] = hash_json(environment)
    result_path.write_text(json.dumps(replay_result), encoding="utf-8")
    environment_path.write_text(json.dumps(environment), encoding="utf-8")
    service.import_external_replay(
        run_id,
        candidate_id,
        actor=reproducer,
        result_path=result_path,
        environment_path=environment_path,
    )

    authority = Actor("judge-2", "human_judge")
    report = AuthorityKernel(project).evaluate(run_id, candidate_id, authority=authority)
    assert report.eligible is False, report.to_dict()
    assert report.detailed_checks["external_isolation_attested"] is False
    assert report.detailed_checks["clean_replay_passed"] is False
    with pytest.raises(PolicyError, match="not authorized"):
        AuthorityKernel(project).authorize(run_id, candidate_id, authority=authority)
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED

    exit_code = main(["--json", "report", "--workspace", str(project.root), "--verified-only"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["data"] == {"certificates": [], "status": "NO_VERIFIED_DISCOVERY"}
