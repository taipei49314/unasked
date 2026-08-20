from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from unasked.budget import BudgetPolicy
from unasked.errors import PolicyError
from unasked.explorer import BoundedExplorer, InvestigationMode
from unasked.policy import Actor, State
from unasked.project import Project
from unasked.providers import JsonSubprocessProvider, ScriptedProvider
from unasked.schemas import SchemaValidationError
from unasked.util import read_json, sha256_bytes
from unasked.workflow import InvestigationService


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
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
        "# Fixture\n\nThe documented command prints expected.\n",
        encoding="utf-8",
    )
    (repository / "tool.py").write_text("print('actual')\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=UNASKED Test",
        "-c",
        "user.email=unasked@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return repository, _git(repository, "rev-parse", "HEAD")


def _budget(**overrides: int) -> BudgetPolicy:
    value = {
        "schema_version": "0.1.0",
        "max_turns": 8,
        "max_provider_calls": 8,
        "max_tool_calls": 4,
        "max_candidates": 2,
        "max_experiments": 2,
        "max_experiment_commands": 4,
        "max_wall_seconds": 120,
        "max_request_bytes": 262_144,
        "max_response_bytes": 65_536,
        "max_total_request_bytes": 1_048_576,
        "max_file_bytes": 65_536,
        "max_search_matches": 16,
        "max_inventory_entries": 100,
        "max_observations": 100,
    }
    value.update(overrides)
    return BudgetPolicy.from_dict(value)


def _project(
    tmp_path: Path,
    *,
    model: str = "fixture-model",
    model_provider: str = "scripted",
) -> tuple[Project, str, dict, dict]:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    explorer = Actor("explorer-1", "explorer")
    run = project.create_run(
        repository,
        commit=commit,
        actor=explorer,
        model_provider=model_provider,
        model_name=model,
    )
    service = InvestigationService(project)
    service.observe(run["run_id"], actor=explorer)
    observations = project.records(run["run_id"], "observations")
    claim = next(
        item
        for item in observations
        if item["kind"] == "CLAIM" and "prints expected" in item["statement"]
    )
    source = next(
        item
        for item in observations
        if item["kind"] == "STRUCTURE" and '"path":"tool.py"' in item["statement"]
    )
    return project, run["run_id"], claim, source


def _proposal(claim_id: str, source_id: str) -> dict:
    return {
        "action": "PROPOSE",
        "expectation": {
            "expectation_type": "explicit",
            "statement": "The documented command should print expected.",
            "reasoning_chain": ["The README states an unconditional behavior claim."],
            "source_observation_ids": [claim_id],
            "strength": "strong",
        },
        "candidate": {
            "observation_ids": [source_id],
            "discrepancy": "The executable may print actual instead of expected.",
            "materiality_question": "Would this change release confidence?",
            "main_hypothesis": "Runtime output contradicts the README claim.",
            "benign_alternatives": ["The README may describe another invocation."],
            "falsification_conditions": ["The command prints expected."],
            "minimal_experiment": "Run a fixed minimal command.",
            "supporting_outcomes": ["stdout equals actual"],
            "falsifying_outcomes": ["stdout equals expected"],
            "inconclusive_outcomes": ["the interpreter cannot run"],
            "estimated_seconds": 5,
            "risk_level": "low",
            "risks": ["sandbox-only process execution"],
        },
        "plan": {
            "commands": [
                {
                    "command_id": "CMD-PROBE",
                    "argv": [sys.executable, "-c", "print('actual')"],
                    "working_directory": ".",
                    "purpose": "Capture the exact runtime output.",
                    "expected_observation": "stdout is actual or expected.",
                }
            ],
            "support_criteria": ["stdout equals actual"],
            "falsify_criteria": ["stdout equals expected"],
            "inconclusive_criteria": ["the command cannot run"],
            "outcome_assertions": [
                {
                    "assertion_id": "A-SUPPORT",
                    "command_id": "CMD-PROBE",
                    "field": "STDOUT_SHA256",
                    "operator": "EQUALS",
                    "expected": sha256_bytes(f"actual{os.linesep}".encode()),
                    "classification": "SUPPORTS",
                },
                {
                    "assertion_id": "A-FALSIFY",
                    "command_id": "CMD-PROBE",
                    "field": "STDOUT_SHA256",
                    "operator": "EQUALS",
                    "expected": sha256_bytes(f"expected{os.linesep}".encode()),
                    "classification": "FALSIFIES",
                },
            ],
            "wall_seconds": 20,
            "cpu_seconds": 20,
            "disk_bytes": 10_000_000,
            "processes": 4,
            "mutation_scope": "SANDBOX_ONLY",
        },
    }


def test_bounded_explorer_creates_evidence_but_never_certifies_m0(tmp_path: Path) -> None:
    project, run_id, claim, source = _project(tmp_path)
    provider = ScriptedProvider(
        [
            {"action": "READ_FILE", "path": "README.md", "max_bytes": 4096},
            _proposal(claim["observation_id"], source["observation_id"]),
            {"action": "STOP", "reason": "ENOUGH_EVIDENCE"},
        ],
        model_name="fixture-model",
    )
    result = BoundedExplorer(project, provider, _budget()).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
        allowed_executables=[sys.executable],
        auto_execute=True,
    )

    assert result["status"] == "COMPLETED"
    assert result["stop_reason"] == "ENOUGH_EVIDENCE"
    assert result["budget"]["consumed"]["provider_calls"] == 3
    assert result["budget"]["consumed"]["tool_calls"] == 1
    assert result["budget"]["consumed"]["candidates"] == 1
    assert result["budget"]["consumed"]["experiments"] == 1
    candidate = project.list_candidates(run_id)[0]
    assert candidate["current_state"] == State.SUPPORTED.value
    assert result["result"]["verified_count"] == 0
    assert result["certification"] == {
        "status": "NON_CERTIFYING",
        "reason_codes": [
            "BENCHMARK_NOT_INDEPENDENTLY_SEALED",
            "DEVELOPMENT_PROVIDER_NON_CERTIFYING",
        ],
        "m0_demonstrated": False,
        "engineering_demo_completed": True,
        "allowed_claim": "A research harness for blind, evidence-gated repository investigation.",
    }
    run_root = project.paths(run_id).root
    assert not (run_root / "custody-attestation.json").exists()
    assert (run_root / "investigation" / "turns.jsonl").is_file()
    assert (
        project.candidate_dir(run_id, candidate["candidate_id"]) / "explorer-provenance.json"
    ).is_file()
    assert project.verify_ledger(run_id)["valid"] is True


def test_model_prose_and_requested_state_cannot_create_a_candidate(tmp_path: Path) -> None:
    project, run_id, claim, source = _project(tmp_path)
    unsafe = _proposal(claim["observation_id"], source["observation_id"])
    unsafe["confidence"] = 1.0
    unsafe["requested_state"] = "VERIFIED"
    provider = ScriptedProvider(
        [unsafe, {"action": "STOP", "reason": "DONE"}],
        model_name="fixture-model",
    )

    result = BoundedExplorer(project, provider, _budget()).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
    )

    assert result["status"] == "COMPLETED"
    assert project.list_candidates(run_id) == []
    assert result["result"]["verified_count"] == 0
    turns = (project.paths(run_id).root / "investigation" / "turns.jsonl").read_text(
        encoding="utf-8"
    )
    assert '"action_status":"REJECTED"' in turns


def test_provider_budget_stops_before_second_call(tmp_path: Path) -> None:
    project, run_id, _, _ = _project(tmp_path)
    provider = ScriptedProvider(
        [
            {"action": "READ_FILE", "path": "README.md", "max_bytes": 4096},
            {"action": "STOP", "reason": "SHOULD_NOT_RUN"},
        ],
        model_name="fixture-model",
    )

    result = BoundedExplorer(project, provider, _budget(max_provider_calls=1)).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
    )

    assert result["status"] == "BUDGET_EXHAUSTED"
    assert result["stop_reason"] == "MAX_PROVIDER_CALLS"
    assert result["budget"]["consumed"]["provider_calls"] == 1
    assert result["budget"]["consumed"]["tool_calls"] == 1
    assert result["certification"]["engineering_demo_completed"] is True


def test_provider_identity_is_frozen_before_investigation(tmp_path: Path) -> None:
    project, run_id, _, _ = _project(tmp_path)
    provider = ScriptedProvider([{"action": "STOP"}], model_name="different-model")

    with pytest.raises(PolicyError, match="does not match"):
        BoundedExplorer(
            project,
            provider,
            _budget(),
            mode=InvestigationMode.FULL_EVIDENCE_GATED,
        ).run(run_id, actor=Actor("explorer-1", "explorer"))

    assert not (project.paths(run_id).root / "investigation").exists()


def test_persisted_investigation_result_stays_non_certifying(tmp_path: Path) -> None:
    project, run_id, _, _ = _project(tmp_path)
    provider = ScriptedProvider([b"not-json", {"action": "STOP"}], model_name="fixture-model")
    result = BoundedExplorer(project, provider, _budget()).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
    )
    persisted = read_json(project.paths(run_id).root / "investigation" / "result.json")

    assert result["status"] == "COMPLETED"
    assert result["result"]["candidate_count"] == 0
    assert persisted["certification"]["m0_demonstrated"] is False
    assert persisted["certification"]["status"] == "NON_CERTIFYING"


def test_investigation_rejects_unbound_or_invalid_knowledge_scan(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    run = project.create_run(
        repository,
        commit=commit,
        actor=Actor("explorer-1", "explorer"),
        model_provider="scripted",
        model_name="fixture-model",
    )
    scan_path = project.paths(run["run_id"]).root / "knowledge-scan.json"
    scan_path.write_text("{}", encoding="utf-8")

    with pytest.raises(SchemaValidationError):
        BoundedExplorer(
            project,
            ScriptedProvider([{"action": "STOP"}], model_name="fixture-model"),
            _budget(),
        ).run(run["run_id"], actor=Actor("explorer-1", "explorer"))

    assert not (project.paths(run["run_id"]).root / "investigation").exists()


def test_investigation_requires_explorer_capabilities_before_writing_start(
    tmp_path: Path,
) -> None:
    project, run_id, _, _ = _project(tmp_path)

    with pytest.raises(PolicyError, match="lacks required capability"):
        BoundedExplorer(
            project,
            ScriptedProvider([{"action": "STOP"}], model_name="fixture-model"),
            _budget(),
        ).run(run_id, actor=Actor("system", "system"))

    assert not (project.paths(run_id).root / "investigation").exists()


def test_provider_timeout_is_bounded_and_persisted_as_normal_budget_stop(
    tmp_path: Path,
) -> None:
    project, run_id, _, _ = _project(
        tmp_path,
        model="timeout-model",
        model_provider="json-subprocess",
    )
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", "import sys,time; sys.stdin.read(); time.sleep(3)"],
        model_name="timeout-model",
        timeout_seconds=5,
    )

    result = BoundedExplorer(project, provider, _budget(max_wall_seconds=1)).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
    )

    assert result["status"] == "BUDGET_EXHAUSTED"
    assert result["stop_reason"] == "MAX_WALL_SECONDS"
    assert result["provider_failed"] is False
    assert (project.paths(run_id).root / "investigation" / "result.json").is_file()


def test_budget_expiring_before_provider_call_does_not_become_provider_failure(
    tmp_path: Path,
) -> None:
    project, run_id, _, _ = _project(tmp_path)
    provider = ScriptedProvider([{"action": "STOP"}], model_name="fixture-model")
    ticks = iter((0.0, 0.0, 2.0))

    def clock() -> float:
        return next(ticks, 2.0)

    result = BoundedExplorer(project, provider, _budget(max_wall_seconds=1), clock=clock).run(
        run_id,
        actor=Actor("explorer-1", "explorer"),
    )

    assert result["status"] == "BUDGET_EXHAUSTED"
    assert result["stop_reason"] == "MAX_WALL_SECONDS"
    assert result["provider_failed"] is False
    assert result["budget"]["consumed"]["provider_calls"] == 0


def test_experiment_command_count_is_frozen_budget_dimension(tmp_path: Path) -> None:
    project, run_id, claim, source = _project(tmp_path)
    provider = ScriptedProvider(
        [
            _proposal(claim["observation_id"], source["observation_id"]),
            {"action": "STOP", "reason": "DONE"},
        ],
        model_name="fixture-model",
    )

    result = BoundedExplorer(
        project,
        provider,
        _budget(max_experiment_commands=1),
    ).run(run_id, actor=Actor("explorer-1", "explorer"))

    assert result["status"] == "BUDGET_EXHAUSTED"
    assert result["stop_reason"] == "MAX_EXPERIMENT_COMMANDS"
    assert project.list_candidates(run_id) == []
    assert result["budget"]["consumed"]["candidates"] == 0
