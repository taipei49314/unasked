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


def _prepared_candidate(tmp_path: Path) -> tuple[Project, InvestigationService, str, str, str]:
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
                "argv": [sys.executable, "-c", "print('actual')"],
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
        disk_bytes=10_000_000,
        processes=4,
    )
    result = service.execute_experiment(
        run_id,
        candidate_id,
        actor=Actor("executor-1", "sandbox_executor"),
        allowed_executables=[sys.executable],
    )
    assert result["status"] == "SUCCEEDED"
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
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED

    authority = Actor("judge-2", "human_judge")
    report = AuthorityKernel(project).evaluate(run_id, candidate_id, authority=authority)
    assert report.eligible is False
    assert report.detailed_checks["clean_replay_passed"] is False
    with pytest.raises(PolicyError, match="not authorized"):
        AuthorityKernel(project).authorize(run_id, candidate_id, authority=authority)
    assert project.current_state(run_id, candidate_id) is State.REPRODUCED


def test_external_evidence_can_authorize_a_structurally_complete_certificate(
    tmp_path: Path,
    capsys,
) -> None:
    project, service, run_id, candidate_id, evidence_hash = _prepared_candidate(tmp_path)
    bundle = project.read_candidate(run_id, candidate_id)
    experiment = read_json(
        project.candidate_dir(run_id, candidate_id) / "experiment" / "result.json"
    )
    plan = read_json(project.candidate_dir(run_id, candidate_id) / "experiment" / "plan.json")
    replay_commands = [
        service.store.put_bytes(
            canonical_json(execution),
            media_type="application/json",
            original_name=f"external-replay-command-{index}.json",
        )
        for index, execution in enumerate(experiment["executions"], start=1)
    ]
    isolation_receipt = service.store.put_bytes(
        canonical_json(
            {
                "issuer": "test-external-isolator",
                "claims": [
                    "NETWORK_ISOLATED",
                    "RESOURCE_LIMITS_ENFORCED",
                    "SECRET_FREE",
                ],
                "status": "ATTESTED",
            }
        ),
        media_type="application/json",
        original_name="external-isolation-receipt.json",
    )
    input_manifest = {
        "target_snapshot_hash": project.get_target(run_id)["snapshot_hash"],
        "plan_hash": hash_json(plan),
        "allowed_executables": sorted(
            {command["argv"][0] for command in plan["commands"]} | {"git"}
        ),
    }
    reproducer = Actor("reproducer-1", "independent_reproducer")
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
    replay_result["environment_hash"] = hash_json(environment)
    result_path.write_text(json.dumps(replay_result), encoding="utf-8")
    service.import_external_replay(
        run_id,
        candidate_id,
        actor=reproducer,
        result_path=result_path,
        environment_path=environment_path,
    )

    authority = Actor("judge-2", "human_judge")
    report = AuthorityKernel(project).evaluate(run_id, candidate_id, authority=authority)
    assert report.eligible is True, report.to_dict()
    authorized = AuthorityKernel(project).authorize(run_id, candidate_id, authority=authority)
    assert authorized["verdict"]["status"] == "VERIFIED"
    assert authorized["certificate"]["status"] == "VERIFIED"
    assert project.current_state(run_id, candidate_id) is State.VERIFIED
    audit = AuthorityKernel(project).audit_certificate(run_id, candidate_id)
    assert audit["valid"] is True, audit

    certificate_path = project.candidate_dir(run_id, candidate_id) / "certificate.yaml"
    tampered_certificate = read_json(certificate_path)
    tampered_certificate["decision_impact"] += " Altered after issuance."
    certificate_path.write_text(json.dumps(tampered_certificate), encoding="utf-8")
    exit_code = main(["--json", "report", "--workspace", str(project.root), "--verified-only"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 4
    assert payload["error"]["code"] == "INTEGRITY_ERROR"
