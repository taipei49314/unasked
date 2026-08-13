from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from unasked.budget import DEFAULT_M0_BUDGET, BudgetPolicy
from unasked.cli import main
from unasked.errors import IntegrityError, PolicyError, UsageError
from unasked.explorer import BoundedExplorer, InvestigationMode
from unasked.policy import Actor
from unasked.project import Project
from unasked.protocol import load_protocol, protocol_hash
from unasked.providers import ScriptedProvider
from unasked.trials import manifest_digest
from unasked.util import canonical_json, hash_json, read_json, write_json
from unasked.workflow import InvestigationService


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    ).stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "README.md").write_text("# Trial binding fixture\n", encoding="utf-8")
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


def _preregistration(
    commit: str,
    *,
    variant: str = "full-evidence-gated-system",
    budget: BudgetPolicy = DEFAULT_M0_BUDGET,
) -> dict:
    manifest = {
        "suite_id": "M0-SUITE-BINDING",
        "cases": [{"case_id": "P-1", "kind": "POSITIVE", "impact_weight": 1}],
        "custody": {
            "status": "UNSEALED",
            "independent": False,
            "sealed_before_explorer": False,
        },
    }
    return {
        "schema_version": "0.1.0",
        "record_type": "M0_TRIAL_PREREGISTRATION",
        "registration_id": "REG-P-1",
        "suite_id": manifest["suite_id"],
        "case_id": "P-1",
        "variant": variant,
        "registered_at": "2026-08-13T00:00:00Z",
        "manifest_hash": manifest_digest(manifest),
        "protocol_hash": protocol_hash(load_protocol()),
        "budget_policy_hash": budget.sha256,
        "target_commit": commit,
        "model": {"provider": "scripted", "name": "fixture-model"},
    }


def _trial_project(
    tmp_path: Path,
    *,
    variant: str = "full-evidence-gated-system",
) -> tuple[Project, dict, dict]:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    preregistration = _preregistration(commit, variant=variant)
    run = project.create_run(
        repository,
        commit=commit,
        actor=Actor("explorer-1", "explorer"),
        model_provider="scripted",
        model_name="fixture-model",
        trial_preregistration=preregistration,
        budget_policy=DEFAULT_M0_BUDGET,
    )
    return project, run, preregistration


def test_trial_run_freezes_preregistration_budget_and_run_created_payload(
    tmp_path: Path,
) -> None:
    project, run, preregistration = _trial_project(tmp_path)
    paths = project.paths(run["run_id"])

    assert read_json(paths.trial_preregistration) == preregistration
    assert read_json(paths.budget_policy) == DEFAULT_M0_BUDGET.to_dict()
    assert run["budget_policy_hash"] == DEFAULT_M0_BUDGET.sha256
    assert run["trial_binding"] == {
        "registration_id": preregistration["registration_id"],
        "suite_id": preregistration["suite_id"],
        "case_id": preregistration["case_id"],
        "variant": preregistration["variant"],
        "preregistration_hash": hash_json(preregistration),
        "manifest_hash": preregistration["manifest_hash"],
    }
    event = project.ledger(run["run_id"]).read_all()[0]
    assert event["event_type"] == "RUN_CREATED"
    assert event["payload"] == {
        "target_snapshot_hash": run["target"]["snapshot_hash"],
        "protocol_hash": run["protocol"]["sha256"],
        "context_manifest_hash": run["context_manifest_hash"],
        "knowledge_boundary_hash": run["knowledge_boundary_hash"],
        "trial_preregistration_hash": hash_json(preregistration),
        "budget_policy_hash": DEFAULT_M0_BUDGET.sha256,
    }


def test_trial_pair_or_mismatched_preregistration_never_creates_a_run(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    preregistration = _preregistration(commit)

    with pytest.raises(UsageError, match="supplied together"):
        project.create_run(
            repository,
            commit=commit,
            actor=Actor("explorer-1", "explorer"),
            trial_preregistration=preregistration,
        )
    assert project.list_runs() == []

    preregistration["target_commit"] = "0" * 40
    with pytest.raises(PolicyError, match="immutable run inputs"):
        project.create_run(
            repository,
            commit=commit,
            actor=Actor("explorer-1", "explorer"),
            model_provider="scripted",
            model_name="fixture-model",
            trial_preregistration=preregistration,
            budget_policy=DEFAULT_M0_BUDGET,
        )
    assert project.list_runs() == []


@pytest.mark.parametrize("tamper", ["preregistration", "budget", "protocol", "run_created"])
def test_trial_tamper_is_rejected_before_any_provider_call(
    tmp_path: Path,
    tamper: str,
) -> None:
    project, run, _ = _trial_project(tmp_path)
    run_id = run["run_id"]
    InvestigationService(project).observe(run_id, actor=Actor("explorer-1", "explorer"))
    paths = project.paths(run_id)
    if tamper == "preregistration":
        document = read_json(paths.trial_preregistration)
        document["registration_id"] = "REG-TAMPERED"
        write_json(paths.trial_preregistration, document)
    elif tamper == "budget":
        document = read_json(paths.budget_policy)
        document["max_provider_calls"] -= 1
        write_json(paths.budget_policy, document)
    elif tamper == "protocol":
        document = read_json(paths.protocol)
        document["high_level_prompt"] += " Tampered."
        write_json(paths.protocol, document)
    else:
        events = project.ledger(run_id).read_all()
        events[0]["payload"]["target_snapshot_hash"] = "0" * 64
        previous = None
        for event in events:
            event["previous_event_hash"] = previous
            event["event_hash"] = hash_json(
                {key: value for key, value in event.items() if key != "event_hash"}
            )
            previous = event["event_hash"]
        paths.ledger.write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))
    provider = ScriptedProvider([{"action": "STOP"}], model_name="fixture-model")

    with pytest.raises(IntegrityError, match="binding is invalid"):
        BoundedExplorer(project, provider, DEFAULT_M0_BUDGET).run(
            run_id,
            actor=Actor("explorer-1", "explorer"),
        )

    assert provider._index == 0
    assert not (paths.root / "investigation").exists()


def test_trial_mode_mismatch_and_baseline_mismatch_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project, run, _ = _trial_project(tmp_path)
    run_id = run["run_id"]
    InvestigationService(project).observe(run_id, actor=Actor("explorer-1", "explorer"))
    provider = ScriptedProvider([{"action": "STOP"}], model_name="fixture-model")

    with pytest.raises(PolicyError, match="mode does not match"):
        BoundedExplorer(
            project,
            provider,
            DEFAULT_M0_BUDGET,
            mode=InvestigationMode.READ_ONLY_LLM,
        ).run(run_id, actor=Actor("explorer-1", "explorer"))
    assert provider._index == 0

    exit_code = main(
        [
            "--json",
            "baselines",
            "run",
            "--workspace",
            str(project.root),
            "--run",
            run_id,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 3
    assert payload["error"]["code"] == "POLICY_DENIED"


def test_legacy_run_payload_and_file_set_remain_unchanged(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    project = Project.create(tmp_path / "workspace")
    run = project.create_run(
        repository,
        commit=commit,
        actor=Actor("explorer-1", "explorer"),
    )
    paths = project.paths(run["run_id"])

    assert "trial_binding" not in run
    assert "budget_policy_hash" not in run
    assert not paths.trial_preregistration.exists()
    assert not paths.budget_policy.exists()
    assert project.ledger(run["run_id"]).read_all()[0]["payload"] == {
        "target_snapshot_hash": run["target"]["snapshot_hash"],
        "protocol_hash": run["protocol"]["sha256"],
        "context_manifest_hash": run["context_manifest_hash"],
        "knowledge_boundary_hash": run["knowledge_boundary_hash"],
    }


def test_init_cli_requires_the_pair_before_creating_a_workspace(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, commit = _repository(tmp_path)
    workspace = tmp_path / "workspace"
    preregistration_path = tmp_path / "preregistration.json"
    write_json(preregistration_path, _preregistration(commit))

    exit_code = main(
        [
            "--json",
            "init",
            str(repository),
            "--commit",
            commit,
            "--workspace",
            str(workspace),
            "--trial-preregistration",
            str(preregistration_path),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["error"]["code"] == "INVALID_INPUT"
    assert not workspace.exists()
