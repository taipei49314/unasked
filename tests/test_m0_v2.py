from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_attestations import _common, _envelope, _policy
from test_trial_redteam import _fixture as _legacy_baseline_fixture
from test_trials import PROTOCOL_HASH, _manifest, _results

from unasked.artifacts import ArtifactStore
from unasked.authority import AuthorityKernel
from unasked.cli import main
from unasked.errors import IntegrityError
from unasked.ledger import EventLedger
from unasked.project import Project
from unasked.schemas import SchemaValidationError
from unasked.trials import (
    ABLATION_VARIANTS,
    _verify_matrix_run_result,
    aggregate_trials,
    certify_m0_v2,
)
from unasked.trust import parse_strict_json
from unasked.util import canonical_json, hash_json, sha256_bytes

NOW = "2026-08-13T08:00:00Z"
SNAPSHOT = "b" * 64
HASH = "a" * 64
FAKE_RUN_BYTES = b'{"fake":"run"}'
BLOCKERS = [
    "ACTOR_IDENTITIES_NOT_AUTHENTICATED",
    "CUSTODY_NOT_AUTHENTICATED",
    "EXTERNAL_ATTESTATION_TRUST_ROOT_NOT_VERIFIED",
    "EXTERNAL_CHECKPOINT_NOT_VERIFIED",
]


class FakeProject:
    def __init__(
        self,
        workspace: Path,
        run_id: str,
        ledger_path: Path,
        *,
        case_id: str,
        variant: str,
        manifest_hash: str,
    ) -> None:
        self.root = workspace
        self.artifacts_root = workspace / "artifacts"
        self.artifacts_root.mkdir(parents=True, exist_ok=True)
        self._run_id = run_id
        self._ledger_path = ledger_path
        self._case_id = case_id
        self._variant = variant
        self._manifest_hash = manifest_hash
        (workspace / "run.json").parent.mkdir(parents=True, exist_ok=True)
        (workspace / "run.json").write_bytes(FAKE_RUN_BYTES)

    def get_run(self, run_id: str) -> dict:
        assert run_id == self._run_id
        return {
            "run_id": run_id,
            "protocol": {"sha256": PROTOCOL_HASH},
            "model": {"provider": "test", "name": "test"},
            "budget_policy_hash": HASH,
            "trial_binding": {
                "suite_id": "M0-SUITE-1",
                "case_id": self._case_id,
                "variant": self._variant,
                "manifest_hash": self._manifest_hash,
                "preregistration_hash": HASH,
            },
        }

    def get_target(self, run_id: str) -> dict:
        assert run_id == self._run_id
        return {"snapshot_hash": SNAPSHOT}

    def validate_trial_binding(self, run_id: str) -> tuple[dict, object]:
        assert run_id == self._run_id
        return (
            {
                "manifest_hash": self._manifest_hash,
                "protocol_hash": PROTOCOL_HASH,
                "budget_policy_hash": HASH,
            },
            SimpleNamespace(sha256=HASH),
        )

    def paths(self, run_id: str) -> SimpleNamespace:
        assert run_id == self._run_id
        discoveries = self.root / "discoveries"
        discoveries.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            ledger=self._ledger_path,
            discoveries=discoveries,
            run=self.root / "run.json",
        )

    def ledger(self, run_id: str) -> EventLedger:
        return EventLedger(self._ledger_path, run_id=run_id)

    def candidate_dir(self, run_id: str, candidate_id: str) -> Path:
        assert run_id == self._run_id
        return self.root / "discoveries" / candidate_id


@dataclass(frozen=True)
class M0Case:
    kwargs: dict
    base: Path
    matrix: dict


def _write(path: Path, data: bytes) -> dict[str, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": path.relative_to(path.parents[2]).as_posix(), "sha256": sha256_bytes(data)}


def _audit(report: dict, index: dict) -> dict:
    checks = {
        "report_recomputed": False,
        "index_binding_valid": False,
        "index_coverage_complete": False,
        "preregistration_bound": False,
        "run_identity_bound": False,
        "protocol_and_budget_bound": False,
        "ledger_heads_match": False,
        "result_artifacts_bound": False,
        "certificate_graphs_valid": False,
        "finding_flags_match_evidence": False,
    }
    value = {
        "schema_version": "0.1.0",
        "audit_type": "M0_TRIAL_EVIDENCE_AUDIT",
        "suite_id": report["suite_id"],
        "manifest_hash": report["manifest_hash"],
        "protocol_hash": PROTOCOL_HASH,
        "report_hash": report["report_hash"],
        "evidence_index_hash": index["index_hash"],
        "recomputed_report_hash": report["report_hash"],
        "audit_result": "FAIL",
        "structural_checks": checks,
        "authorization_checks": {
            "actor_identities_authenticated": False,
            "custody_authenticated": False,
            "external_attestation_trust_root_verified": False,
            "external_checkpoint_verified": False,
        },
        "certification_blockers": BLOCKERS,
        "entries": [],
        "status": "NON_CERTIFYING",
        "m0_demonstrated": False,
        "reason_codes": BLOCKERS,
    }
    value["audit_hash"] = hash_json(value)
    return value


def _evaluation_gates(*, production: bool) -> dict[str, bool]:
    return {
        "matrix_complete": True,
        "independent_custody": production,
        "sealed_before_explorer": production,
        "actor_identities_authenticated": production,
        "isolation_attestations_authenticated": production,
        "ledger_checkpoints_authenticated": production,
        "certificate_graphs_valid": production,
        "positive_threshold_met": production,
        "control_threshold_met": True,
        "clean_replay_complete": True,
        "context_provenance_complete": production,
        "inputs_immutable": production,
    }


def _make_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, production: bool) -> M0Case:
    policy_bytes, _, keys = _policy()
    policy = parse_strict_json(policy_bytes)
    policy["mode"] = "PRODUCTION" if production else "SHADOW"
    policy_bytes = canonical_json(policy)
    policy_sha256 = sha256_bytes(policy_bytes)
    manifest = aggregate_trials(_manifest(), _results(_manifest()))["manifest"]
    results = _results(manifest) if production else _results(manifest)
    if not production:
        for result in results:
            for finding in result["findings"]:
                for name in tuple(finding):
                    if name != "case_id":
                        finding[name] = False
    report = aggregate_trials(manifest, results)
    report_bytes = canonical_json(report)
    manifest_bytes = canonical_json(manifest)
    custody_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    custody_envelope = _envelope(
        custody_type,
        {
            **_common(policy_sha256, "actor-2"),
            "suite_id": report["suite_id"],
            "manifest_sha256": sha256_bytes(manifest_bytes),
            "case_commitment_sha256": HASH,
            "sealed_at": "2026-08-10T00:00:00Z",
            "explorer_development_started_at": "2026-08-11T00:00:00Z",
            "independent_custody": True,
            "sealed_before_explorer": True,
            "hidden_case_count": 7,
            "positive_case_count": 5,
            "control_case_count": 2,
            "explorer_ground_truth_access": False,
            "evaluator_access": False,
            "directional_steering": False,
        },
        manifest_bytes,
        keys["CUSTODIAN"],
    )
    base = tmp_path / "bundle"
    projects: dict[Path, FakeProject] = {}
    matrix_entries = []
    index_entries = []
    run_bindings = []
    findings = {
        (result["variant"], finding["case_id"]): finding
        for result in report["variant_results"]
        for finding in result["findings"]
    }
    for variant in ABLATION_VARIANTS:
        for case in manifest["cases"]:
            case_id = case["case_id"]
            key = f"{variant}-{case_id}"
            run_id = f"RUN-{key}"
            workspace = base / "workspaces" / key
            result_bytes = canonical_json({"run_id": run_id, "result": "authenticated"})
            result_path = base / "evidence" / key / "result.json"
            result_ref = _write(result_path, result_bytes)
            ledger_path = base / "evidence" / key / "ledger.jsonl"
            ledger = EventLedger(ledger_path, run_id=run_id)
            ledger.append(
                "RUN_CREATED",
                {"target_snapshot_hash": SNAPSHOT, "protocol_hash": PROTOCOL_HASH},
                occurred_at="2026-08-13T06:00:00Z",
            )
            trusted = findings[(variant, case_id)]["verified"]
            certificate_bindings = []
            certificate_refs = []
            if trusted:
                candidate_id = f"CANDIDATE-{case_id}"
                ledger.append(
                    "AUTHORIZATION_COMMITTED",
                    {"candidate_id": candidate_id},
                    occurred_at="2026-08-13T07:00:00Z",
                )
                authority_predicate = canonical_json({"candidate": candidate_id})
                c_pre_predicate = canonical_json({"candidate": candidate_id, "checkpoint": True})
                authority_ref = _write(
                    base / "evidence" / key / f"{candidate_id}-authority.dsse.json",
                    authority_predicate,
                )
                c_pre_ref = _write(
                    base / "evidence" / key / f"{candidate_id}-c-pre.dsse.json",
                    c_pre_predicate,
                )
                certificate_bindings.append(
                    {
                        "candidate_id": candidate_id,
                        "authority_envelope": authority_ref,
                        "c_pre_checkpoint_envelope": c_pre_ref,
                    }
                )
                certificate_refs.append({"candidate_id": candidate_id, "certificate_sha256": HASH})
                verdict_path = workspace / "discoveries" / candidate_id / "verdict.json"
                verdict_path.parent.mkdir(parents=True, exist_ok=True)
                verdict_path.write_bytes(
                    canonical_json(
                        {
                            "authority_actor": {
                                "actor_id": "actor-1",
                                "role": "HUMAN_JUDGE",
                            }
                        }
                    )
                )
                (verdict_path.parent / "authorization-commit.json").write_bytes(b"{}")
            ledger_bytes = ledger_path.read_bytes()
            isolation_type = "https://schemas.unasked.dev/attestations/isolation/v0.4"
            isolation_envelope = _envelope(
                isolation_type,
                {
                    **_common(policy_sha256, "actor-3"),
                    "suite_id": report["suite_id"],
                    "case_id": case_id,
                    "variant": variant,
                    "run_id": run_id,
                    "started_at": "2026-08-13T06:00:00Z",
                    "completed_at": "2026-08-13T07:00:00Z",
                    "target_snapshot_hash": SNAPSHOT,
                    "protocol_hash": PROTOCOL_HASH,
                    "executor_actor_id": "executor-external",
                    "isolation_class": "EXTERNAL_SEALED",
                    "network_mode": "DENY_ALL",
                    "filesystem_mode": "IMMUTABLE_INPUT_ISOLATED_OUTPUT",
                    "input_manifest_sha256": HASH,
                    "command_records_sha256": HASH,
                    "output_manifest_sha256": HASH,
                    "residual_state_detected": False,
                },
                result_bytes,
                keys["ISOLATION_ATTESTER"],
            )
            isolation_ref = _write(
                base / "evidence" / key / "isolation.dsse.json", isolation_envelope
            )
            ledger_report = ledger.verify(raise_on_error=True)
            checkpoint_type = "https://schemas.unasked.dev/attestations/ledger-checkpoint/v0.4"
            checkpoint_envelope = _envelope(
                checkpoint_type,
                {
                    **_common(policy_sha256, "actor-4"),
                    "suite_id": report["suite_id"],
                    "case_id": case_id,
                    "variant": variant,
                    "run_id": run_id,
                    "entry_count": ledger_report.entries,
                    "head_event_hash": ledger_report.last_hash,
                    "ledger_sha256": sha256_bytes(ledger_bytes),
                    "target_snapshot_hash": SNAPSHOT,
                    "protocol_hash": PROTOCOL_HASH,
                    "checkpointed_at": "2026-08-13T07:00:00Z",
                },
                ledger_bytes,
                keys["LEDGER_WITNESS"],
            )
            checkpoint_ref = _write(
                base / "evidence" / key / "final-checkpoint.dsse.json",
                checkpoint_envelope,
            )
            ledger_ref = {
                "path": ledger_path.relative_to(base).as_posix(),
                "sha256": sha256_bytes(ledger_bytes),
            }
            matrix_entry = {
                "variant": variant,
                "case_id": case_id,
                "run_id": run_id,
                "workspace": workspace.relative_to(base).as_posix(),
                "result": result_ref,
                "ledger": ledger_ref,
                "isolation_envelope": isolation_ref,
                "final_checkpoint_envelope": checkpoint_ref,
                "certificate_bindings": certificate_bindings,
            }
            index_entry = {
                "variant": variant,
                "case_id": case_id,
                "workspace": matrix_entry["workspace"],
                "run_id": run_id,
                "run_sha256": sha256_bytes(FAKE_RUN_BYTES),
                "preregistration_hash": HASH,
                "budget_policy_hash": HASH,
                "ledger": {"entries": ledger_report.entries, "last_hash": ledger_report.last_hash},
                "result_ref": {
                    "kind": "BASELINE_RESULT",
                    "storage": "CAS",
                    "sha256": result_ref["sha256"],
                },
                "certificate_refs": certificate_refs,
            }
            index_entries.append(index_entry)
            matrix_entries.append(matrix_entry)
            run_bindings.append(
                {
                    "variant": variant,
                    "case_id": case_id,
                    "run_id": run_id,
                    "target_snapshot_hash": SNAPSHOT,
                    "result_sha256": result_ref["sha256"],
                    "isolation_envelope_sha256": isolation_ref["sha256"],
                    "ledger_checkpoint_envelope_sha256": checkpoint_ref["sha256"],
                    "evidence_index_entry_sha256": hash_json(index_entry),
                    "certificate_set_sha256": hash_json(
                        [
                            {
                                "candidate_id": item["candidate_id"],
                                "authority_envelope_sha256": item["authority_envelope"]["sha256"],
                                "c_pre_checkpoint_envelope_sha256": item[
                                    "c_pre_checkpoint_envelope"
                                ]["sha256"],
                            }
                            for item in certificate_bindings
                        ]
                    ),
                }
            )
            projects[workspace.resolve()] = FakeProject(
                workspace,
                run_id,
                ledger_path,
                case_id=case_id,
                variant=variant,
                manifest_hash=report["manifest_hash"],
            )
    index = {
        "schema_version": "0.1.0",
        "index_type": "M0_TRIAL_EVIDENCE_INDEX",
        "suite_id": report["suite_id"],
        "manifest_hash": report["manifest_hash"],
        "protocol_hash": PROTOCOL_HASH,
        "report_hash": report["report_hash"],
        "entries": index_entries,
    }
    index["index_hash"] = hash_json(index)
    index_bytes = canonical_json(index)
    audit = _audit(report, index)
    audit_bytes = canonical_json(audit)
    matrix = {
        "schema_version": "0.4.0",
        "suite_id": report["suite_id"],
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "protocol_hash": PROTOCOL_HASH,
        "entries": matrix_entries,
    }
    matrix["matrix_sha256"] = hash_json(matrix)
    matrix_bytes = canonical_json(matrix)
    run_bindings.sort(key=lambda item: (item["variant"], item["case_id"]))
    observed = {
        "trusted_verified_positives": 3 if production else 0,
        "false_verified_controls": 0,
        "false_verified_claims": 0,
        "claimed_verified_total": 3 if production else 0,
        "clean_replay_verified": 3 if production else 0,
        "context_provenance_complete": production,
        "target_snapshot_immutable": True,
        "hidden_inputs_immutable": production,
        "scoring_policy_immutable": True,
    }
    evaluation_envelope = _envelope(
        "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4",
        {
            **_common(policy_sha256, "actor-5"),
            "suite_id": report["suite_id"],
            "manifest_sha256": sha256_bytes(manifest_bytes),
            "protocol_hash": PROTOCOL_HASH,
            "custody_envelope_sha256": sha256_bytes(custody_envelope),
            "report_sha256": sha256_bytes(report_bytes),
            "evidence_index_sha256": sha256_bytes(index_bytes),
            "audit_sha256": sha256_bytes(audit_bytes),
            "run_matrix_sha256": sha256_bytes(matrix_bytes),
            "run_count": 35,
            "variant_count": 5,
            "case_count": 7,
            "run_bindings": run_bindings,
            "thresholds": {
                "positive_cases_required": 3,
                "positive_cases_total": 5,
                "control_false_verified_max": 0,
                "clean_replay_rate_required": "1.000000",
                "run_count_required": 35,
                "variant_count_required": 5,
                "case_count_required": 7,
            },
            "observed": observed,
            "gates": _evaluation_gates(production=production),
            "status": "THRESHOLDS_MET" if production else "NOT_MET",
        },
        report_bytes,
        keys["TRIAL_EVALUATOR"],
    )
    certification_envelope = _envelope(
        "https://schemas.unasked.dev/attestations/m0-certification/v0.4",
        {
            **_common(policy_sha256, "actor-6"),
            "suite_id": report["suite_id"],
            "manifest_sha256": sha256_bytes(manifest_bytes),
            "protocol_hash": PROTOCOL_HASH,
            "custody_envelope_sha256": sha256_bytes(custody_envelope),
            "trial_evaluation_envelope_sha256": sha256_bytes(evaluation_envelope),
            "evidence_index_sha256": sha256_bytes(index_bytes),
            "audit_sha256": sha256_bytes(audit_bytes),
            "run_matrix_sha256": sha256_bytes(matrix_bytes),
            "decision": "M0_DEMONSTRATED" if production else "M0_NOT_DEMONSTRATED",
            "claim": (
                "Demonstrated blind discovery of reproducible discrepancies on a sealed "
                "evaluation set."
                if production
                else "M0_NOT_DEMONSTRATED"
            ),
            "limitations": [],
        },
        evaluation_envelope,
        keys["M0_CERTIFIER"],
    )
    monkeypatch.setattr(Project, "open", lambda path: projects[Path(path).resolve()])
    monkeypatch.setattr("unasked.trials._verify_matrix_run_result", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        AuthorityKernel,
        "audit_certificate_v2",
        lambda *_args, **_kwargs: {
            "valid": True,
            "certificate_sha256": HASH,
            "checks": {"evidence_complete": True},
            "detailed_checks": {},
            "gate_report": {
                "checks": {"evidence_complete": True},
                "detailed_checks": {
                    "unasked_attestation": True,
                    "declared_knowledge_boundary": True,
                    "novelty_review_approved": True,
                    "clean_replay_passed": True,
                    "counterevidence_complete": True,
                    "materiality_review_approved": True,
                    "experiment_environment_bound": True,
                    "replay_environment_bound": True,
                    "replay_input_bound": True,
                    "replay_outputs_bound": True,
                    "artifact_integrity": True,
                    "source_replay": True,
                    "ledger_integrity": True,
                    "legal_state_history": True,
                    "protocol_frozen": True,
                    "snapshot_bound": True,
                    "identity_bound": True,
                },
            },
        },
    )
    return M0Case(
        {
            "certification_envelope_bytes": certification_envelope,
            "trial_evaluation_envelope_bytes": evaluation_envelope,
            "trust_policy_bytes": policy_bytes,
            "trust_policy_sha256": policy_sha256,
            "manifest_bytes": manifest_bytes,
            "custody_envelope_bytes": custody_envelope,
            "report_bytes": report_bytes,
            "evidence_index_bytes": index_bytes,
            "audit_bytes": audit_bytes,
            "run_matrix_bytes": matrix_bytes,
            "base_path": base,
            "now": NOW,
        },
        base,
        matrix,
    )


def test_shadow_matrix_returns_authenticated_not_demonstrated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)

    result = certify_m0_v2(**case.kwargs)

    assert result["status"] == "M0_NOT_DEMONSTRATED"
    assert result["m0_demonstrated"] is False
    assert result["authenticated_v2_audit"] is True
    assert result["legacy_structural_audit_authoritative"] is False


def test_production_matrix_can_demonstrate_only_from_authenticated_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=True)

    result = certify_m0_v2(**case.kwargs)

    assert result["status"] == "M0_DEMONSTRATED"
    assert result["m0_demonstrated"] is True


def test_matrix_omission_and_exact_file_tamper_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    omitted = dict(case.matrix)
    omitted["entries"] = omitted["entries"][:-1]
    omitted["matrix_sha256"] = hash_json(
        {name: value for name, value in omitted.items() if name != "matrix_sha256"}
    )
    with pytest.raises(SchemaValidationError):
        certify_m0_v2(**{**case.kwargs, "run_matrix_bytes": canonical_json(omitted)})

    first = case.matrix["entries"][0]["result"]
    (case.base / first["path"]).write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="hash mismatch"):
        certify_m0_v2(**case.kwargs)


def _write_cli_inputs(case: M0Case) -> dict[str, Path]:
    mapping = {
        "certification-envelope": "certification_envelope_bytes",
        "trial-evaluation-envelope": "trial_evaluation_envelope_bytes",
        "trust-policy": "trust_policy_bytes",
        "manifest": "manifest_bytes",
        "custody-envelope": "custody_envelope_bytes",
        "report": "report_bytes",
        "evidence-index": "evidence_index_bytes",
        "audit": "audit_bytes",
        "run-matrix": "run_matrix_bytes",
    }
    paths = {}
    for option, argument in mapping.items():
        path = case.base / f"{option}.json"
        path.write_bytes(case.kwargs[argument])
        paths[option] = path
    return paths


def _certify_cli_args(paths: dict[str, Path], policy_sha256: str) -> list[str]:
    args = ["--json", "trials", "certify"]
    for option, path in paths.items():
        args.extend((f"--{option}", str(path)))
    args.extend(("--trust-policy-sha256", policy_sha256))
    return args


def test_cli_shadow_golden_and_v2_input_exit_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    paths = _write_cli_inputs(case)
    args = _certify_cli_args(paths, case.kwargs["trust_policy_sha256"])

    assert main(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["status"] == "M0_NOT_DEMONSTRATED"
    assert payload["data"]["authenticated_v2_audit"] is True

    partial = ["--json", "trials", "certify", "--report", str(paths["report"])]
    partial.extend(("--certification-envelope", str(paths["certification-envelope"])))
    assert main(partial) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "INVALID_INPUT"

    unsafe_matrix = parse_strict_json(case.kwargs["run_matrix_bytes"])
    unsafe_matrix["entries"][0]["workspace"] = "../escape"
    unsafe_matrix["matrix_sha256"] = hash_json(
        {name: value for name, value in unsafe_matrix.items() if name != "matrix_sha256"}
    )
    paths["run-matrix"].write_bytes(canonical_json(unsafe_matrix))
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "INVALID_INPUT"
    paths["run-matrix"].write_bytes(case.kwargs["run_matrix_bytes"])

    report = parse_strict_json(paths["report"].read_bytes())
    report["suite_id"] = "tampered-suite"
    paths["report"].write_bytes(canonical_json(report))
    assert main(args) == 4
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "INTEGRITY_ERROR"


def test_cli_legacy_certify_returns_exact_non_demonstration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = aggregate_trials(_manifest(), _results(_manifest()))
    path = tmp_path / "report.json"
    path.write_bytes(canonical_json(report))

    assert main(["--json", "trials", "certify", "--report", str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"] == {
        "authenticated_v2_audit": False,
        "claim": "M0_NOT_DEMONSTRATED",
        "legacy_structural_audit_authoritative": False,
        "m0_demonstrated": False,
        "reason_codes": ["AUTHENTICATED_V2_EVIDENCE_NOT_PROVIDED"],
        "report_hash": report["report_hash"],
        "status": "M0_NOT_DEMONSTRATED",
    }


def test_matrix_baseline_result_is_bound_to_real_run_cas_and_ledger(tmp_path: Path) -> None:
    report, index, base = _legacy_baseline_fixture(tmp_path)
    indexed = index["entries"][0]
    project = Project.open(base / indexed["workspace"])
    run_id = indexed["run_id"]
    result_bytes = ArtifactStore(project.artifacts_root).read_bytes(indexed["result_ref"]["sha256"])
    entry = {
        "variant": indexed["variant"],
        "case_id": indexed["case_id"],
        "run_id": run_id,
        "result": {
            "path": "evidence/result.json",
            "sha256": indexed["result_ref"]["sha256"],
        },
    }

    _verify_matrix_run_result(
        entry,
        indexed,
        project=project,
        run=project.get_run(run_id),
        target=project.get_target(run_id),
        events=project.ledger(run_id).read_all(),
        result_bytes=result_bytes,
        protocol_digest=report["variant_results"][0]["protocol_hash"],
    )

    substituted = {**indexed, "result_ref": {**indexed["result_ref"], "sha256": HASH}}
    with pytest.raises(IntegrityError, match="result hashes"):
        _verify_matrix_run_result(
            entry,
            substituted,
            project=project,
            run=project.get_run(run_id),
            target=project.get_target(run_id),
            events=project.ledger(run_id).read_all(),
            result_bytes=result_bytes,
            protocol_digest=report["variant_results"][0]["protocol_hash"],
        )
