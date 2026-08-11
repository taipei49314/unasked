from __future__ import annotations

import json
import subprocess
from pathlib import Path

from unasked.cli import main
from unasked.policy import Actor
from unasked.project import Project
from unasked.trials import ABLATION_VARIANTS, manifest_digest
from unasked.util import write_json
from unasked.workflow import InvestigationService


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def _workspace(tmp_path: Path) -> tuple[Project, str, Path]:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "README.md").write_text("# Clean development fixture\n", encoding="utf-8")
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
    project = Project.create(tmp_path / "workspace")
    actor = Actor("explorer-cli", "explorer")
    run = project.create_run(
        repository,
        commit=_git(repository, "rev-parse", "HEAD"),
        actor=actor,
        model_provider="scripted",
        model_name="cli-model",
    )
    InvestigationService(project).observe(run["run_id"], actor=actor)
    return project, run["run_id"], repository


def _budget() -> dict:
    return {
        "schema_version": "0.1.0",
        "max_turns": 2,
        "max_provider_calls": 2,
        "max_tool_calls": 1,
        "max_candidates": 1,
        "max_experiments": 1,
        "max_experiment_commands": 2,
        "max_wall_seconds": 60,
        "max_request_bytes": 262_144,
        "max_response_bytes": 65_536,
        "max_total_request_bytes": 524_288,
        "max_file_bytes": 65_536,
        "max_search_matches": 8,
        "max_inventory_entries": 100,
        "max_observations": 100,
    }


def test_investigate_cli_emits_one_non_certifying_json_envelope(tmp_path: Path, capsys) -> None:
    project, run_id, repository = _workspace(tmp_path)
    budget_path = tmp_path / "budget.json"
    responses_path = tmp_path / "responses.jsonl"
    provider_path = tmp_path / "provider.json"
    write_json(budget_path, _budget())
    responses_path.write_text('{"action":"STOP","reason":"NO_CANDIDATE"}\n', encoding="utf-8")
    write_json(
        provider_path,
        {
            "kind": "scripted",
            "model": "cli-model",
            "responses_file": responses_path.name,
        },
    )
    original_head = _git(repository, "rev-parse", "HEAD")

    exit_code = main(
        [
            "--json",
            "investigate",
            "--workspace",
            str(project.root),
            "--run",
            run_id,
            "--budget",
            str(budget_path),
            "--provider-config",
            str(provider_path),
        ]
    )
    raw = capsys.readouterr().out
    payload = json.loads(raw)

    assert exit_code == 0
    assert set(payload) == {"ok", "command", "data"}
    assert payload["command"] == "investigate"
    assert payload["data"]["status"] == "COMPLETED"
    assert payload["data"]["stop_reason"] == "NO_CANDIDATE"
    assert payload["data"]["certification"]["status"] == "NON_CERTIFYING"
    assert payload["data"]["certification"]["m0_demonstrated"] is False
    assert _git(repository, "rev-parse", "HEAD") == original_head
    assert _git(repository, "status", "--porcelain") == ""


def _trial_inputs() -> tuple[dict, list[dict]]:
    manifest = {
        "suite_id": "UNSEALED-DEV",
        "cases": [
            *[
                {"case_id": f"P{index}", "kind": "POSITIVE", "impact_weight": 1}
                for index in range(1, 6)
            ],
            {"case_id": "C1", "kind": "CONTROL", "impact_weight": 0},
            {"case_id": "C2", "kind": "CONTROL", "impact_weight": 0},
        ],
        "custody": {
            "status": "UNSEALED",
            "independent": False,
            "sealed_before_explorer": False,
        },
    }
    digest = manifest_digest(manifest)
    flags = {
        "claimed_verified": False,
        "verified": False,
        "unasked": False,
        "novel": False,
        "replay_passed": False,
        "counterevidence_passed": False,
        "external_authority": False,
        "decision_impact": False,
        "evidence_complete": False,
    }
    results = [
        {
            "variant": variant,
            "manifest_hash": digest,
            "protocol_hash": "a" * 64,
            "normalized_budget": 10,
            "findings": [{"case_id": case["case_id"], **flags} for case in manifest["cases"]],
        }
        for variant in ABLATION_VARIANTS
    ]
    return manifest, results


def test_trials_cli_evaluates_unsealed_but_refuses_certification(tmp_path: Path, capsys) -> None:
    manifest, results = _trial_inputs()
    manifest_path = tmp_path / "manifest.json"
    results_path = tmp_path / "results.json"
    report_path = tmp_path / "report.json"
    write_json(manifest_path, manifest)
    write_json(results_path, results)

    evaluate_code = main(
        [
            "--json",
            "trials",
            "evaluate",
            "--manifest",
            str(manifest_path),
            "--results",
            str(results_path),
        ]
    )
    evaluated = json.loads(capsys.readouterr().out)
    assert evaluate_code == 0
    assert evaluated["data"]["status"] == "NON_CERTIFYING"
    assert evaluated["data"]["m0_demonstrated"] is False
    write_json(report_path, evaluated["data"])

    certify_code = main(["--json", "trials", "certify", "--report", str(report_path)])
    rejected = json.loads(capsys.readouterr().out)
    assert certify_code == 3
    assert rejected["error"]["code"] == "POLICY_DENIED"
    assert rejected["command"] == "trials certify"
