from __future__ import annotations

import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from unasked.artifacts import ArtifactStore
from unasked.baseline import run_deterministic_baseline
from unasked.budget import DEFAULT_M0_BUDGET
from unasked.errors import PolicyError, UsageError
from unasked.explorer import BoundedExplorer, InvestigationMode
from unasked.policy import Actor
from unasked.project import Project
from unasked.protocol import load_protocol, protocol_hash
from unasked.providers import ScriptedProvider
from unasked.schemas import SchemaValidationError, validate_or_raise
from unasked.trials import aggregate_trials, audit_trial_evidence, certify_m0, manifest_digest
from unasked.util import canonical_json, hash_json, read_json, sha256_file
from unasked.workflow import InvestigationService

_VARIANT = "deterministic-detectors-only"
_CASE_ID = "P-1"
_BLOCKERS = [
    "ACTOR_IDENTITIES_NOT_AUTHENTICATED",
    "CUSTODY_NOT_AUTHENTICATED",
    "EXTERNAL_ATTESTATION_TRUST_ROOT_NOT_VERIFIED",
    "EXTERNAL_CHECKPOINT_NOT_VERIFIED",
]


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    ).stdout.strip()


def _false_finding(case_id: str = _CASE_ID) -> dict:
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


def _rehash(document: dict, field: str) -> None:
    document[field] = hash_json({key: value for key, value in document.items() if key != field})


def _fixture(tmp_path: Path) -> tuple[dict, dict, Path]:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "README.md").write_text("# Red-team fixture\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=UNASKED Red Team",
        "-c",
        "user.email=redteam@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    commit = _git(repository, "rev-parse", "HEAD")

    manifest = {
        "suite_id": "M0-REDTEAM",
        "cases": [{"case_id": _CASE_ID, "kind": "POSITIVE", "impact_weight": 1}],
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
        "registration_id": "REG-REDTEAM-P1",
        "suite_id": manifest["suite_id"],
        "case_id": _CASE_ID,
        "variant": _VARIANT,
        "registered_at": "2026-08-13T00:00:00Z",
        "manifest_hash": manifest_hash,
        "protocol_hash": frozen_protocol_hash,
        "budget_policy_hash": DEFAULT_M0_BUDGET.sha256,
        "target_commit": commit,
        "model": {"provider": "none", "name": "not-configured"},
    }
    base_path = tmp_path / "evidence"
    workspace = base_path / "workspace"
    project = Project.create(workspace)
    run = project.create_run(
        repository,
        commit=commit,
        actor=Actor("explorer-1", "explorer"),
        trial_preregistration=preregistration,
        budget_policy=DEFAULT_M0_BUDGET,
    )
    run_id = run["run_id"]
    baseline = run_deterministic_baseline(project, run_id)
    metadata = ArtifactStore(project.artifacts_root).put_bytes(
        canonical_json(baseline),
        media_type=baseline["integration"]["media_type"],
        original_name="deterministic-baseline.json",
    )
    project.ledger(run_id).append(
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
    variant_result = {
        "variant": _VARIANT,
        "manifest_hash": manifest_hash,
        "protocol_hash": frozen_protocol_hash,
        "normalized_budget": "1",
        "findings": [_false_finding()],
    }
    report = aggregate_trials(manifest, [variant_result])
    ledger = project.ledger(run_id).verify()
    evidence_index = {
        "schema_version": "0.1.0",
        "index_type": "M0_TRIAL_EVIDENCE_INDEX",
        "suite_id": manifest["suite_id"],
        "manifest_hash": manifest_hash,
        "protocol_hash": frozen_protocol_hash,
        "report_hash": report["report_hash"],
        "entries": [
            {
                "variant": _VARIANT,
                "case_id": _CASE_ID,
                "workspace": "workspace",
                "run_id": run_id,
                "run_sha256": sha256_file(project.paths(run_id).run),
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
    _rehash(evidence_index, "index_hash")
    return report, evidence_index, base_path


def test_audit_schema_rejects_pass_laundering_and_pass_stays_non_certifying(
    tmp_path: Path,
) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)
    assert audit["audit_result"] == "PASS"
    assert audit["status"] == "NON_CERTIFYING"
    assert audit["m0_demonstrated"] is False
    with pytest.raises(PolicyError):
        certify_m0(report)

    laundered = deepcopy(audit)
    laundered["structural_checks"]["ledger_heads_match"] = False
    _rehash(laundered, "audit_hash")
    with pytest.raises(SchemaValidationError):
        validate_or_raise("trial-evidence-audit", laundered)


def test_audit_schema_requires_all_four_canonical_trust_blockers(tmp_path: Path) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)
    assert audit["certification_blockers"] == _BLOCKERS

    missing = deepcopy(audit)
    missing["certification_blockers"].pop()
    _rehash(missing, "audit_hash")
    with pytest.raises(SchemaValidationError):
        validate_or_raise("trial-evidence-audit", missing)


@pytest.mark.parametrize("locator", ["../escape", "/absolute", "C:/absolute"])
def test_unsafe_workspace_locators_fail_before_evidence_reads(tmp_path: Path, locator: str) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    evidence_index["entries"][0]["workspace"] = locator
    _rehash(evidence_index, "index_hash")
    with pytest.raises(UsageError, match="relative path|outside"):
        audit_trial_evidence(report, evidence_index, base_path=base_path)


def test_duplicate_entry_and_run_reuse_cannot_satisfy_index_coverage(tmp_path: Path) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    duplicate = deepcopy(evidence_index)
    duplicate["entries"].append(deepcopy(duplicate["entries"][0]))
    _rehash(duplicate, "index_hash")
    with pytest.raises(SchemaValidationError):
        audit_trial_evidence(report, duplicate, base_path=base_path)

    reused = deepcopy(evidence_index)
    extra = deepcopy(reused["entries"][0])
    extra["case_id"] = "P-EXTRA"
    reused["entries"].append(extra)
    _rehash(reused, "index_hash")
    audit = audit_trial_evidence(report, reused, base_path=base_path)
    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["index_coverage_complete"] is False

    omitted = deepcopy(evidence_index)
    omitted["entries"] = []
    _rehash(omitted, "index_hash")
    audit = audit_trial_evidence(report, omitted, base_path=base_path)
    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["index_coverage_complete"] is False


def test_true_report_flags_without_certificate_graph_fail_closed(tmp_path: Path) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    finding = report["variant_results"][0]["findings"][0]
    for key in finding:
        if key != "case_id":
            finding[key] = True
    report = aggregate_trials(report["manifest"], report["variant_results"])
    evidence_index["report_hash"] = report["report_hash"]
    _rehash(evidence_index, "index_hash")

    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)
    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["finding_flags_match_evidence"] is False
    assert audit["entries"][0]["certificate_audits"] == []
    assert audit["entries"][0]["derived_finding"] == _false_finding()


def test_audit_output_is_path_and_clock_independent(tmp_path: Path) -> None:
    report, evidence_index, first_base = _fixture(tmp_path)
    first = audit_trial_evidence(report, evidence_index, base_path=first_base)

    second_base = tmp_path / "relocated" / "deep" / "evidence"
    second_base.parent.mkdir(parents=True)
    shutil.copytree(first_base, second_base)
    second = audit_trial_evidence(report, evidence_index, base_path=second_base)

    assert second == first
    rendered = canonical_json(first).decode("utf-8")
    assert str(first_base) not in rendered
    assert str(second_base) not in rendered
    assert "2026-08-13T00:00:00Z" not in rendered


@pytest.mark.parametrize(
    "hidden_field",
    ["kind", "ground_truth", "expected_result", "minimum_evidence", "materiality"],
)
def test_preregistration_schema_rejects_hidden_semantic_fields(
    tmp_path: Path, hidden_field: str
) -> None:
    _, evidence_index, base_path = _fixture(tmp_path)
    entry = evidence_index["entries"][0]
    project = Project.open(base_path / entry["workspace"])
    preregistration = read_json(project.paths(entry["run_id"]).trial_preregistration)
    preregistration[hidden_field] = "sealed-value"
    with pytest.raises(SchemaValidationError):
        validate_or_raise("trial-preregistration", preregistration)


def test_provider_request_does_not_receive_preregistration_metadata(tmp_path: Path) -> None:
    _, evidence_index, base_path = _fixture(tmp_path)
    baseline_entry = evidence_index["entries"][0]
    baseline_project = Project.open(base_path / baseline_entry["workspace"])
    baseline_paths = baseline_project.paths(baseline_entry["run_id"])
    preregistration = read_json(baseline_paths.trial_preregistration)
    preregistration.update(
        {
            "registration_id": "REG-SECRET-OPAQUE",
            "case_id": "CASE-SECRET-OPAQUE",
            "variant": "read-only-llm-reviewer",
            "model": {"provider": "scripted", "name": "capture-model"},
        }
    )
    repository = tmp_path / "target"
    capture_project = Project.create(tmp_path / "capture-workspace")
    run = capture_project.create_run(
        repository,
        commit=preregistration["target_commit"],
        actor=Actor("explorer-capture", "explorer"),
        model_provider="scripted",
        model_name="capture-model",
        trial_preregistration=preregistration,
        budget_policy=DEFAULT_M0_BUDGET,
    )
    InvestigationService(capture_project).observe(
        run["run_id"], actor=Actor("explorer-capture", "explorer")
    )

    class CapturingProvider(ScriptedProvider):
        def __init__(self) -> None:
            super().__init__([{"action": "STOP", "reason": "DONE"}], model_name="capture-model")
            self.requests: list[dict] = []

        def invoke(self, request: dict, **kwargs):
            self.requests.append(deepcopy(request))
            return super().invoke(request, **kwargs)

    provider = CapturingProvider()
    BoundedExplorer(
        capture_project,
        provider,
        DEFAULT_M0_BUDGET,
        mode=InvestigationMode.READ_ONLY_LLM,
    ).run(run["run_id"], actor=Actor("explorer-capture", "explorer"))

    assert len(provider.requests) == 1
    rendered = canonical_json(provider.requests[0]).decode("utf-8")
    for sealed_value in (
        preregistration["registration_id"],
        preregistration["suite_id"],
        preregistration["case_id"],
        preregistration["registered_at"],
        preregistration["manifest_hash"],
        hash_json(preregistration),
    ):
        assert sealed_value not in rendered


def test_workspace_symlink_escape_is_rejected(tmp_path: Path) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    outside = tmp_path / "outside"
    shutil.copytree(base_path / "workspace", outside)
    link = base_path / "linked-workspace"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")
    evidence_index["entries"][0]["workspace"] = "linked-workspace"
    _rehash(evidence_index, "index_hash")
    with pytest.raises(UsageError, match="outside"):
        audit_trial_evidence(report, evidence_index, base_path=base_path)


def test_legacy_run_is_not_backfilled_and_audits_as_structural_failure(tmp_path: Path) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    repository = tmp_path / "target"
    commit = _git(repository, "rev-parse", "HEAD")
    legacy = Project.create(base_path / "legacy")
    run = legacy.create_run(
        repository,
        commit=commit,
        actor=Actor("legacy-explorer", "explorer"),
    )
    run_id = run["run_id"]
    baseline = run_deterministic_baseline(legacy, run_id)
    metadata = ArtifactStore(legacy.artifacts_root).put_bytes(
        canonical_json(baseline),
        media_type=baseline["integration"]["media_type"],
        original_name="deterministic-baseline.json",
    )
    legacy.ledger(run_id).append(
        "DETERMINISTIC_BASELINE_COMPLETED",
        {
            "baseline_run_id": baseline["baseline_run_id"],
            "signal_count": baseline["signal_count"],
            "snapshot_hash": baseline["snapshot_hash"],
            "protocol_hash": baseline["protocol_hash"],
        },
        actor=Actor("legacy-baseline", "explorer").to_dict(),
        artifact_refs=[metadata.to_reference()],
    )
    ledger = legacy.ledger(run_id).verify()
    entry = evidence_index["entries"][0]
    entry.update(
        {
            "workspace": "legacy",
            "run_id": run_id,
            "run_sha256": sha256_file(legacy.paths(run_id).run),
            "ledger": {"entries": ledger.entries, "last_hash": ledger.last_hash},
            "result_ref": {
                "kind": "BASELINE_RESULT",
                "storage": "CAS",
                "sha256": metadata.sha256,
            },
        }
    )
    _rehash(evidence_index, "index_hash")
    before = sorted(path.relative_to(legacy.root).as_posix() for path in legacy.root.rglob("*"))

    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)

    after = sorted(path.relative_to(legacy.root).as_posix() for path in legacy.root.rglob("*"))
    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["preregistration_bound"] is False
    assert legacy.validate_trial_binding(run_id) is None
    assert after == before


def test_forged_certificate_ref_and_actor_strings_cannot_remove_trust_boundary(
    tmp_path: Path,
) -> None:
    report, evidence_index, base_path = _fixture(tmp_path)
    evidence_index["entries"][0]["certificate_refs"] = [
        {"candidate_id": "D-FORGED", "certificate_sha256": "0" * 64}
    ]
    _rehash(evidence_index, "index_hash")
    audit = audit_trial_evidence(report, evidence_index, base_path=base_path)

    assert audit["audit_result"] == "FAIL"
    assert audit["structural_checks"]["certificate_graphs_valid"] is False
    assert not any(audit["authorization_checks"].values())
    assert audit["certification_blockers"] == _BLOCKERS
