from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from unasked.artifacts import ArtifactStore
from unasked.baseline import run_deterministic_baseline
from unasked.budget import DEFAULT_M0_BUDGET
from unasked.cli import main
from unasked.errors import IntegrityError, UsageError
from unasked.policy import Actor
from unasked.project import Project
from unasked.protocol import load_protocol, protocol_hash
from unasked.trials import aggregate_trials, audit_trial_evidence, manifest_digest
from unasked.util import canonical_json, hash_json, sha256_file, write_json


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
    (repository / "README.md").write_text("# Audit fixture\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "fixture@example.invalid")
    _git(repository, "config", "user.name", "Fixture")
    _git(repository, "add", "-A")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


def _false_finding(case_id: str) -> dict:
    return {
        "case_id": case_id,
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


def _baseline_audit_fixture(tmp_path: Path) -> tuple[dict, dict, Path]:
    repository, commit = _repository(tmp_path)
    manifest = {
        "suite_id": "M0-SUITE-AUDIT",
        "cases": [{"case_id": "P-1", "kind": "POSITIVE", "impact_weight": 1}],
        "custody": {
            "status": "UNSEALED",
            "independent": False,
            "sealed_before_explorer": False,
        },
    }
    manifest_hash = manifest_digest(manifest)
    frozen_protocol_hash = protocol_hash(load_protocol())
    preregistration = {
        "schema_version": "0.1.0",
        "record_type": "M0_TRIAL_PREREGISTRATION",
        "registration_id": "REG-P-1-BASELINE",
        "suite_id": manifest["suite_id"],
        "case_id": "P-1",
        "variant": "deterministic-detectors-only",
        "registered_at": "2026-08-13T00:00:00Z",
        "manifest_hash": manifest_hash,
        "protocol_hash": frozen_protocol_hash,
        "budget_policy_hash": DEFAULT_M0_BUDGET.sha256,
        "target_commit": commit,
        "model": {"provider": "none", "name": "not-configured"},
    }
    workspace = tmp_path / "evidence" / "workspace"
    project = Project.create(workspace)
    run = project.create_run(
        repository,
        commit=commit,
        actor=Actor("explorer-1", "explorer"),
        trial_preregistration=preregistration,
        budget_policy=DEFAULT_M0_BUDGET,
    )
    baseline = run_deterministic_baseline(project, run["run_id"])
    metadata = ArtifactStore(project.artifacts_root).put_bytes(
        canonical_json(baseline),
        media_type=baseline["integration"]["media_type"],
        original_name="deterministic-baseline.json",
    )
    project.ledger(run["run_id"]).append(
        "DETERMINISTIC_BASELINE_COMPLETED",
        {
            "baseline_run_id": baseline["baseline_run_id"],
            "signal_count": baseline["signal_count"],
            "snapshot_hash": baseline["snapshot_hash"],
            "protocol_hash": baseline["protocol_hash"],
        },
        actor=Actor("baseline-1", "explorer").to_dict(),
        artifact_refs=[metadata.to_reference()],
    )
    report = aggregate_trials(
        manifest,
        [
            {
                "variant": "deterministic-detectors-only",
                "manifest_hash": manifest_hash,
                "protocol_hash": frozen_protocol_hash,
                "normalized_budget": "1",
                "findings": [_false_finding("P-1")],
            }
        ],
    )
    ledger = project.ledger(run["run_id"]).verify()
    evidence_index = {
        "schema_version": "0.1.0",
        "index_type": "M0_TRIAL_EVIDENCE_INDEX",
        "suite_id": manifest["suite_id"],
        "manifest_hash": manifest_hash,
        "protocol_hash": frozen_protocol_hash,
        "report_hash": report["report_hash"],
        "entries": [
            {
                "variant": "deterministic-detectors-only",
                "case_id": "P-1",
                "workspace": "workspace",
                "run_id": run["run_id"],
                "run_sha256": sha256_file(project.paths(run["run_id"]).run),
                "preregistration_hash": hash_json(preregistration),
                "budget_policy_hash": DEFAULT_M0_BUDGET.sha256,
                "ledger": {"entries": ledger.entries, "last_hash": ledger.last_hash},
                "result_ref": {
                    "kind": "BASELINE_RESULT",
                    "storage": "CAS",
                    "sha256": metadata.sha256,
                },
                "certificate_refs": [],
            }
        ],
    }
    evidence_index["index_hash"] = hash_json(evidence_index)
    return report, evidence_index, tmp_path / "evidence"


def test_structurally_complete_all_false_trial_evidence_can_pass_but_not_certify(
    tmp_path: Path,
) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)

    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)

    assert audit["audit_result"] == "PASS"
    assert all(audit["structural_checks"].values())
    assert audit["status"] == "NON_CERTIFYING"
    assert audit["m0_demonstrated"] is False
    assert not any(audit["authorization_checks"].values())
    assert len(audit["certification_blockers"]) == 4
    assert audit["entries"][0]["derived_finding"] == _false_finding("P-1")
    assert audit["audit_hash"] == hash_json(
        {key: value for key, value in audit.items() if key != "audit_hash"}
    )


def test_index_rollback_is_reported_as_structural_failure(tmp_path: Path) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    evidence_index["entries"][0]["ledger"]["entries"] -= 1
    evidence_index["index_hash"] = hash_json(
        {key: value for key, value in evidence_index.items() if key != "index_hash"}
    )

    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)

    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["ledger_heads_match"] is False


def test_report_and_index_self_hashes_fail_before_evidence_io(tmp_path: Path) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    tampered_report = deepcopy(report)
    tampered_report["report_hash"] = "0" * 64
    with pytest.raises(IntegrityError, match="self-hash"):
        audit_trial_evidence(tampered_report, evidence_index, base_path=base_path)

    tampered_index = deepcopy(evidence_index)
    tampered_index["index_hash"] = "0" * 64
    with pytest.raises(IntegrityError, match="self-hash"):
        audit_trial_evidence(report, tampered_index, base_path=base_path)


@pytest.mark.parametrize(
    "workspace",
    [
        "../outside",
        "..\\outside",
        "/absolute",
        "C:/absolute",
        "C:\\absolute",
        "\\\\server\\share",
    ],
)
def test_unsafe_workspace_locator_is_rejected_before_io(tmp_path: Path, workspace: str) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    evidence_index["entries"][0]["workspace"] = workspace
    evidence_index["index_hash"] = hash_json(
        {key: value for key, value in evidence_index.items() if key != "index_hash"}
    )

    with pytest.raises(UsageError, match="relative path|outside"):
        audit_trial_evidence(report, evidence_index, base_path=base_path)


def _run_audit_cli(
    report: dict,
    evidence_index: dict,
    base_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict]:
    report_path = base_path / "report.json"
    index_path = base_path / "evidence-index.json"
    write_json(report_path, report)
    write_json(index_path, evidence_index)
    exit_code = main(
        [
            "--json",
            "trials",
            "audit",
            "--report",
            str(report_path),
            "--evidence-index",
            str(index_path),
        ]
    )
    return exit_code, json.loads(capsys.readouterr().out)


def test_trials_audit_cli_returns_readable_pass_and_evidence_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    exit_code, payload = _run_audit_cli(report, evidence_index, base_path, capsys)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["data"]["audit_result"] == "PASS"
    assert payload["data"]["status"] == "NON_CERTIFYING"

    evidence_index["entries"][0]["ledger"]["entries"] -= 1
    evidence_index["index_hash"] = hash_json(
        {key: value for key, value in evidence_index.items() if key != "index_hash"}
    )
    exit_code, payload = _run_audit_cli(report, evidence_index, base_path, capsys)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["data"]["audit_result"] == "FAIL"
    assert payload["data"]["structural_checks"]["ledger_heads_match"] is False


def test_trials_audit_cli_schema_and_integrity_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    malformed = deepcopy(report)
    del malformed["suite_id"]
    exit_code, payload = _run_audit_cli(malformed, evidence_index, base_path, capsys)
    assert exit_code == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "SCHEMA_VALIDATION_FAILED"

    broken_hash = deepcopy(report)
    broken_hash["report_hash"] = "0" * 64
    exit_code, payload = _run_audit_cli(broken_hash, evidence_index, base_path, capsys)
    assert exit_code == 4
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INTEGRITY_ERROR"


def test_trials_audit_cli_rejects_report_that_cannot_be_recomputed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report, evidence_index, base_path = _baseline_audit_fixture(tmp_path)
    report["variant_results"][0]["findings"][0]["verified"] = True
    report["report_hash"] = hash_json(
        {key: value for key, value in report.items() if key != "report_hash"}
    )

    exit_code, payload = _run_audit_cli(report, evidence_index, base_path, capsys)

    assert exit_code == 4
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INTEGRITY_ERROR"
