"""Deterministic M0 trial aggregation and fail-closed certification.

The legacy aggregator and structural audit remain deliberately non-certifying. Version 0.4
adds a separate authenticated path that verifies an externally supplied, exact-byte-pinned
trust policy and complete signed evidence bundle. SHADOW or incomplete inputs still yield
the exact negative result ``M0_NOT_DEMONSTRATED``; this package ships no qualifying run.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from unasked.artifacts import ArtifactStore
from unasked.attestations import (
    verify_custody_attestation,
    verify_isolation_attestation,
    verify_ledger_checkpoint,
    verify_m0_certification,
    verify_trial_evaluation,
)
from unasked.authority import AuthorityKernel
from unasked.errors import IntegrityError, PolicyError, UsageError
from unasked.policy import Actor
from unasked.project import Project
from unasked.protocol import protocol_hash
from unasked.schemas import validate_or_raise
from unasked.trust import parse_strict_json
from unasked.util import canonical_json, hash_json, read_json, sha256_bytes, sha256_file

SCHEMA_VERSION = "0.1.0"
METRIC_QUANTUM = Decimal("0.000001")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AblationVariant(StrEnum):
    """The five preregistered comparisons required by the North Star charter."""

    DETERMINISTIC_DETECTORS_ONLY = "deterministic-detectors-only"
    READ_ONLY_LLM_REVIEWER = "read-only-llm-reviewer"
    LLM_TOOLS_NO_EXPERIMENT_GATE = "llm-tools-no-experiment-gate"
    EXPERIMENT_LOOP_WITHOUT_FALSIFIER = "experiment-loop-without-falsifier"
    FULL_EVIDENCE_GATED_SYSTEM = "full-evidence-gated-system"


ABLATION_VARIANTS: tuple[str, ...] = tuple(item.value for item in AblationVariant)
FULL_SYSTEM_VARIANT = AblationVariant.FULL_EVIDENCE_GATED_SYSTEM.value

_FINDING_FLAGS = (
    "claimed_verified",
    "verified",
    "unasked",
    "novel",
    "replay_passed",
    "counterevidence_passed",
    "external_authority",
    "decision_impact",
    "evidence_complete",
)
_AUTHORIZATION_CHECKS = (
    "actor_identities_authenticated",
    "custody_authenticated",
    "external_attestation_trust_root_verified",
    "external_checkpoint_verified",
)
_CERTIFICATION_BLOCKERS = (
    "ACTOR_IDENTITIES_NOT_AUTHENTICATED",
    "CUSTODY_NOT_AUTHENTICATED",
    "EXTERNAL_ATTESTATION_TRUST_ROOT_NOT_VERIFIED",
    "EXTERNAL_CHECKPOINT_NOT_VERIFIED",
)
_ENTRY_CHECKS = (
    "preregistration_bound",
    "run_identity_bound",
    "protocol_and_budget_bound",
    "ledger_head_matches",
    "result_artifact_bound",
    "certificate_set_complete",
    "certificate_graphs_valid",
)
_STRUCTURAL_CHECKS = (
    "report_recomputed",
    "index_binding_valid",
    "index_coverage_complete",
    "preregistration_bound",
    "run_identity_bound",
    "protocol_and_budget_bound",
    "ledger_heads_match",
    "result_artifacts_bound",
    "certificate_graphs_valid",
    "finding_flags_match_evidence",
)
_INVESTIGATION_MODES = {
    "read-only-llm-reviewer": "read_only_llm",
    "llm-tools-no-experiment-gate": "llm_tools_no_experiment_gate",
    "experiment-loop-without-falsifier": "experiment_loop_no_falsifier",
    "full-evidence-gated-system": "full_evidence_gated",
}


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UsageError(f"{name} must be an object.")
    return value


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise UsageError(f"{name} must be an array.")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UsageError(f"{name} must be a non-empty string.")
    return value.strip()


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise UsageError(f"{name} must be a boolean.")
    return value


def _decimal(value: Any, name: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float, str)):
        raise UsageError(f"{name} must be a finite decimal number.")
    if isinstance(value, float) and not math.isfinite(value):
        raise UsageError(f"{name} must be a finite decimal number.")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise UsageError(f"{name} must be a finite decimal number.") from exc
    if not result.is_finite() or result < 0 or (positive and result == 0):
        qualifier = "positive " if positive else "non-negative "
        raise UsageError(f"{name} must be a finite {qualifier}decimal number.")
    return result


def _decimal_text(value: Decimal) -> str:
    return format(value.quantize(METRIC_QUANTUM, rounding=ROUND_HALF_EVEN), ".6f")


def _ratio(numerator: int | Decimal, denominator: int | Decimal) -> str:
    denominator_decimal = Decimal(denominator)
    if denominator_decimal == 0:
        return _decimal_text(Decimal(0))
    return _decimal_text(Decimal(numerator) / denominator_decimal)


def _json_safe(value: Any) -> Any:
    """Return a deterministic JSON-compatible copy without accepting opaque objects."""

    if isinstance(value, Decimal):
        return format(value, "f")
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise UsageError("Trial inputs cannot contain non-finite numbers.")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise UsageError("Trial input object keys must be strings.")
        return {key: _json_safe(value[key]) for key in sorted(value)}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_safe(item) for item in value]
    raise UsageError(f"Trial inputs contain a non-JSON value of type {type(value).__name__}.")


def _normalize_manifest(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, dict]]:
    normalized = _json_safe(manifest)
    suite_id = _text(normalized.get("suite_id"), "manifest.suite_id")
    raw_cases = _sequence(normalized.get("cases"), "manifest.cases")
    cases_by_id: dict[str, dict[str, Any]] = {}
    for index, raw_case in enumerate(raw_cases):
        case = dict(_mapping(raw_case, f"manifest.cases[{index}]"))
        case_id = _text(case.get("case_id"), f"manifest.cases[{index}].case_id")
        if case_id in cases_by_id:
            raise UsageError(f"manifest contains duplicate case_id {case_id!r}.")
        kind = _text(case.get("kind"), f"manifest.cases[{index}].kind").upper()
        if kind not in {"POSITIVE", "CONTROL"}:
            raise UsageError(f"manifest case {case_id!r} kind must be POSITIVE or CONTROL.")
        impact_weight = _decimal(
            case.get("impact_weight"), f"manifest.cases[{index}].impact_weight"
        )
        case.update(
            {
                "case_id": case_id,
                "kind": kind,
                "impact_weight": _decimal_text(impact_weight),
            }
        )
        cases_by_id[case_id] = case

    custody = dict(_mapping(normalized.get("custody"), "manifest.custody"))
    status = _text(custody.get("status"), "manifest.custody.status").upper()
    if status not in {"SEALED", "UNSEALED"}:
        raise UsageError("manifest.custody.status must be SEALED or UNSEALED.")
    custody.update(
        {
            "status": status,
            "independent": _boolean(custody.get("independent"), "manifest.custody.independent"),
            "sealed_before_explorer": _boolean(
                custody.get("sealed_before_explorer"),
                "manifest.custody.sealed_before_explorer",
            ),
        }
    )
    normalized.update(
        {
            "suite_id": suite_id,
            "cases": [cases_by_id[case_id] for case_id in sorted(cases_by_id)],
            "custody": custody,
        }
    )
    return normalized, cases_by_id


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Hash the validated, order-normalized manifest used by variant results."""

    normalized, _ = _normalize_manifest(_mapping(manifest, "manifest"))
    return hash_json(normalized)


def _normalize_finding(
    raw: Any,
    *,
    variant: str,
    index: int,
    cases_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    finding = dict(_mapping(_json_safe(raw), f"{variant}.findings[{index}]"))
    case_id = _text(finding.get("case_id"), f"{variant}.findings[{index}].case_id")
    if case_id not in cases_by_id:
        raise UsageError(f"Variant {variant!r} references unknown case_id {case_id!r}.")
    finding["case_id"] = case_id
    for flag in _FINDING_FLAGS:
        finding[flag] = _boolean(finding.get(flag), f"{variant}.{case_id}.{flag}")
    return finding


def _normalize_variant_result(
    raw: Any,
    *,
    index: int,
    expected_manifest_hash: str,
    cases_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    result = dict(_mapping(_json_safe(raw), f"variant_results[{index}]"))
    variant = _text(result.get("variant"), f"variant_results[{index}].variant")
    if variant not in ABLATION_VARIANTS:
        raise UsageError(
            f"Unknown ablation variant {variant!r}.",
            details={"allowed": list(ABLATION_VARIANTS)},
        )
    claimed_manifest_hash = _text(
        result.get("manifest_hash"), f"variant_results[{index}].manifest_hash"
    ).lower()
    if not _SHA256_RE.fullmatch(claimed_manifest_hash):
        raise UsageError(f"Variant {variant!r} manifest_hash must be a lowercase SHA-256.")
    if claimed_manifest_hash != expected_manifest_hash:
        raise IntegrityError(
            "Variant result is not bound to the supplied manifest.",
            details={
                "variant": variant,
                "expected": expected_manifest_hash,
                "actual": claimed_manifest_hash,
            },
        )
    protocol_hash = _text(
        result.get("protocol_hash"), f"variant_results[{index}].protocol_hash"
    ).lower()
    if not _SHA256_RE.fullmatch(protocol_hash):
        raise UsageError(f"Variant {variant!r} protocol_hash must be a lowercase SHA-256.")
    budget = _decimal(
        result.get("normalized_budget"),
        f"variant_results[{index}].normalized_budget",
        positive=True,
    )
    raw_findings = _sequence(result.get("findings"), f"variant_results[{index}].findings")
    findings_by_id: dict[str, dict[str, Any]] = {}
    for finding_index, raw_finding in enumerate(raw_findings):
        finding = _normalize_finding(
            raw_finding,
            variant=variant,
            index=finding_index,
            cases_by_id=cases_by_id,
        )
        case_id = finding["case_id"]
        if case_id in findings_by_id:
            raise UsageError(f"Variant {variant!r} contains duplicate case_id {case_id!r}.")
        findings_by_id[case_id] = finding
    result.update(
        {
            "variant": variant,
            "manifest_hash": claimed_manifest_hash,
            "protocol_hash": protocol_hash,
            "normalized_budget": _decimal_text(budget),
            "findings": [findings_by_id[case_id] for case_id in sorted(findings_by_id)],
        }
    )
    return result


def _trusted_positive(finding: Mapping[str, Any], kind: str) -> bool:
    return kind == "POSITIVE" and all(finding[flag] for flag in _FINDING_FLAGS)


def _variant_report(
    result: Mapping[str, Any], cases_by_id: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    findings = result["findings"]
    finding_ids = {finding["case_id"] for finding in findings}
    expected_ids = set(cases_by_id)
    coverage_complete = finding_ids == expected_ids

    # Treat either flag as a verification assertion.  A producer cannot hide a
    # false VERIFIED control merely by setting claimed_verified to false.
    claimed = [
        finding for finding in findings if finding["claimed_verified"] or finding["verified"]
    ]
    trusted = [
        finding
        for finding in findings
        if _trusted_positive(finding, cases_by_id[finding["case_id"]]["kind"])
    ]
    false_claims = [
        finding
        for finding in claimed
        if not _trusted_positive(finding, cases_by_id[finding["case_id"]]["kind"])
    ]
    false_controls = [
        finding for finding in claimed if cases_by_id[finding["case_id"]]["kind"] == "CONTROL"
    ]
    positives = [case for case in cases_by_id.values() if case["kind"] == "POSITIVE"]
    controls = [case for case in cases_by_id.values() if case["kind"] == "CONTROL"]

    impact_numerator = sum(
        (
            _decimal(
                cases_by_id[finding["case_id"]]["impact_weight"],
                f"impact_weight[{finding['case_id']}]",
            )
            for finding in trusted
        ),
        Decimal(0),
    )
    budget = _decimal(result["normalized_budget"], "normalized_budget", positive=True)
    replayed_claims = sum(1 for finding in claimed if finding["replay_passed"])
    complete_claims = sum(1 for finding in claimed if finding["evidence_complete"])
    impactful_claims = sum(1 for finding in claimed if finding["decision_impact"])

    return {
        "variant": result["variant"],
        "manifest_hash": result["manifest_hash"],
        "protocol_hash": result["protocol_hash"],
        "normalized_budget": _decimal_text(budget),
        "coverage_complete": coverage_complete,
        "counts": {
            "cases": len(cases_by_id),
            "positive_cases": len(positives),
            "control_cases": len(controls),
            "findings": len(findings),
            "claimed_verified": len(claimed),
            "trusted_verified_positives": len(trusted),
            "false_verified_claims": len(false_claims),
            "false_verified_controls": len(false_controls),
        },
        "metrics": {
            "trusted_discovery_precision": _ratio(len(trusted), len(claimed)),
            "hidden_discovery_recall": _ratio(len(trusted), len(positives)),
            "control_false_positive_rate": _ratio(len(false_controls), len(controls)),
            "false_verified_claim_rate": _ratio(len(false_claims), len(claimed)),
            "clean_reproduction_rate": _ratio(replayed_claims, len(claimed)),
            "decision_impact_rate": _ratio(impactful_claims, len(claimed)),
            "evidence_completeness": _ratio(complete_claims, len(claimed)),
            "impact_weighted_verified_yield": _decimal_text(impact_numerator),
            "tudy": _decimal_text(impact_numerator / budget),
        },
        "trusted_case_ids": sorted(finding["case_id"] for finding in trusted),
        "false_verified_case_ids": sorted(finding["case_id"] for finding in false_claims),
        "false_verified_control_ids": sorted(finding["case_id"] for finding in false_controls),
    }


def aggregate_trials(manifest: dict, variant_results: list[dict]) -> dict[str, Any]:
    """Aggregate five ablation trials into one canonical, self-hashed M0 report.

    Partial ablation coverage remains reportable but cannot demonstrate M0.  A
    manifest binding mismatch is an integrity error, while all gate failures are
    represented explicitly in the returned report.
    """

    normalized_manifest, cases_by_id = _normalize_manifest(_mapping(manifest, "manifest"))
    raw_results = _sequence(variant_results, "variant_results")
    expected_manifest_hash = hash_json(normalized_manifest)

    results_by_variant: dict[str, dict[str, Any]] = {}
    for index, raw_result in enumerate(raw_results):
        result = _normalize_variant_result(
            raw_result,
            index=index,
            expected_manifest_hash=expected_manifest_hash,
            cases_by_id=cases_by_id,
        )
        variant = result["variant"]
        if variant in results_by_variant:
            raise UsageError(f"Duplicate ablation variant {variant!r}.")
        results_by_variant[variant] = result

    normalized_results = [
        results_by_variant[variant]
        for variant in ABLATION_VARIANTS
        if variant in results_by_variant
    ]
    variant_reports = [_variant_report(result, cases_by_id) for result in normalized_results]
    reports_by_variant = {item["variant"]: item for item in variant_reports}
    full = reports_by_variant.get(FULL_SYSTEM_VARIANT)

    positive_cases = sum(1 for case in cases_by_id.values() if case["kind"] == "POSITIVE")
    control_cases = sum(1 for case in cases_by_id.values() if case["kind"] == "CONTROL")
    custody = normalized_manifest["custody"]
    protocol_hashes = {result["protocol_hash"] for result in normalized_results}
    all_claimed_findings = (
        []
        if full is None
        else [
            finding
            for result in normalized_results
            if result["variant"] == FULL_SYSTEM_VARIANT
            for finding in result["findings"]
            if finding["claimed_verified"]
        ]
    )

    gates = {
        "benchmark_sealed": custody["status"] == "SEALED",
        "independent_custody": custody["independent"],
        "sealed_before_explorer": custody["sealed_before_explorer"],
        "case_mix_exact": positive_cases == 5 and control_cases == 2,
        "ablation_coverage_complete": set(results_by_variant) == set(ABLATION_VARIANTS)
        and all(item["coverage_complete"] for item in variant_reports),
        "manifest_binding_complete": all(
            result["manifest_hash"] == expected_manifest_hash for result in normalized_results
        ),
        "protocol_frozen": len(protocol_hashes) == 1 and bool(normalized_results),
        "full_system_case_coverage": full is not None and full["coverage_complete"],
        "positive_threshold_met": full is not None
        and full["counts"]["trusted_verified_positives"] >= 3,
        "control_threshold_met": full is not None
        and full["counts"]["false_verified_controls"] == 0,
        "clean_replay_complete": bool(all_claimed_findings)
        and all(finding["replay_passed"] for finding in all_claimed_findings),
        "context_provenance_complete": bool(all_claimed_findings)
        and all(finding["evidence_complete"] for finding in all_claimed_findings),
        "no_false_verified_claims": full is not None
        and full["counts"]["false_verified_claims"] == 0,
        # This release has no cryptographic custody/evaluator verifier and does
        # not dereference every finding into its certificate, CAS, ledger, run,
        # replay, and protocol bundle.  Declarative input booleans are metrics,
        # never authority.
        "external_evidence_verified": False,
    }
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": "M0_TRIAL_AGGREGATE",
        "suite_id": normalized_manifest["suite_id"],
        "manifest_hash": expected_manifest_hash,
        "manifest": normalized_manifest,
        "ablation_variants": list(ABLATION_VARIANTS),
        "variant_results": normalized_results,
        "variant_reports": variant_reports,
        "gates": gates,
        "status": "NON_CERTIFYING",
        "m0_demonstrated": False,
    }
    report["report_hash"] = hash_json(report)
    return report


def certify_m0(report: dict) -> dict[str, Any]:
    """Recompute a report, then fail closed pending an external evidence verifier."""

    candidate = dict(_mapping(_json_safe(report), "report"))
    claimed_hash = _text(candidate.pop("report_hash", None), "report.report_hash").lower()
    if not _SHA256_RE.fullmatch(claimed_hash) or hash_json(candidate) != claimed_hash:
        raise IntegrityError("M0 report hash mismatch.")

    rebuilt = aggregate_trials(
        dict(_mapping(candidate.get("manifest"), "report.manifest")),
        list(_sequence(candidate.get("variant_results"), "report.variant_results")),
    )
    if canonical_json(rebuilt) != canonical_json(report):
        raise IntegrityError("M0 report does not match deterministic recomputation.")

    custody = rebuilt["manifest"]["custody"]
    if not (
        custody["status"] == "SEALED"
        and custody["independent"]
        and custody["sealed_before_explorer"]
    ):
        raise PolicyError(
            "M0 certification requires independent custody sealed before Explorer development.",
            details={
                "status": custody["status"],
                "independent": custody["independent"],
                "sealed_before_explorer": custody["sealed_before_explorer"],
            },
        )
    if rebuilt["gates"]["external_evidence_verified"] is not True:
        raise PolicyError(
            "M0 certification is unavailable until external custody and every "
            "certificate/CAS/ledger bundle can be independently verified.",
            details={"reason": "EXTERNAL_EVIDENCE_VERIFIER_NOT_IMPLEMENTED"},
        )
    return rebuilt


def _verify_self_hash(document: dict[str, Any], field: str, name: str) -> str:
    claimed = document[field]
    candidate = {key: value for key, value in document.items() if key != field}
    actual = hash_json(candidate)
    if claimed != actual:
        raise IntegrityError(
            f"{name} self-hash mismatch.",
            details={"field": field, "expected": actual, "actual": claimed},
        )
    return actual


def _safe_workspace_paths(
    entries: Sequence[Mapping[str, Any]], base_path: Path
) -> dict[tuple[str, str], Path]:
    base = base_path.expanduser().resolve()
    resolved: dict[tuple[str, str], Path] = {}
    for entry in entries:
        rendered = entry["workspace"]
        locator = Path(rendered)
        posix_locator = PurePosixPath(rendered)
        windows_locator = PureWindowsPath(rendered)
        unsafe = any(
            (
                locator.is_absolute(),
                bool(locator.drive),
                posix_locator.is_absolute(),
                bool(posix_locator.root),
                ".." in posix_locator.parts,
                windows_locator.is_absolute(),
                bool(windows_locator.drive),
                bool(windows_locator.root),
                ".." in windows_locator.parts,
            )
        )
        if unsafe:
            raise UsageError(
                "Trial evidence workspace must be a relative path without parent traversal.",
                details={"workspace": rendered},
            )
        candidate = (base / locator).resolve(strict=False)
        if candidate != base and base not in candidate.parents:
            raise UsageError(
                "Trial evidence workspace resolves outside the evidence index directory.",
                details={"workspace": rendered},
            )
        resolved[(entry["variant"], entry["case_id"])] = candidate
    return resolved


def _false_finding(case_id: str) -> dict[str, Any]:
    return {"case_id": case_id, **{flag: False for flag in _FINDING_FLAGS}}


def _matching_artifact_event(
    events: Sequence[Mapping[str, Any]],
    *,
    event_type: str,
    digest: str,
    path: str | None = None,
    expected_payload: Mapping[str, Any] | None = None,
) -> bool:
    matches = []
    for event in events:
        if event.get("event_type") != event_type:
            continue
        event_payload = event.get("payload", {})
        if path is not None and event_payload != {"path": path, "sha256": digest}:
            continue
        if expected_payload is not None and event_payload != expected_payload:
            continue
        if path is None and not any(
            reference.get("sha256") == digest for reference in event.get("artifact_refs", [])
        ):
            continue
        matches.append(event)
    return len(matches) == 1


def _derive_verified_finding(
    case_id: str,
    certificate_audits: Sequence[Mapping[str, Any]],
    *,
    actual_verified: bool,
    certificate_set_complete: bool,
) -> dict[str, Any]:
    if not actual_verified:
        return _false_finding(case_id)
    audits_valid = (
        certificate_set_complete
        and bool(certificate_audits)
        and all(audit.get("valid") is True for audit in certificate_audits)
    )
    gate_reports = [audit.get("gate_report", {}) for audit in certificate_audits]

    def every_detail(name: str) -> bool:
        return audits_valid and all(
            report.get("detailed_checks", {}).get(name) is True for report in gate_reports
        )

    evidence_complete = audits_valid and all(
        report.get("checks", {}).get("evidence_complete") is True
        and all(
            report.get("detailed_checks", {}).get(name) is True
            for name in (
                "experiment_environment_bound",
                "replay_environment_bound",
                "replay_input_bound",
                "replay_outputs_bound",
                "artifact_integrity",
                "source_replay",
                "ledger_integrity",
                "legal_state_history",
                "protocol_frozen",
                "snapshot_bound",
                "identity_bound",
            )
        )
        for report in gate_reports
    )
    return {
        "case_id": case_id,
        "claimed_verified": True,
        "verified": audits_valid,
        "unasked": every_detail("unasked_attestation"),
        "novel": every_detail("declared_knowledge_boundary")
        and every_detail("novelty_review_approved"),
        "replay_passed": every_detail("clean_replay_passed"),
        "counterevidence_passed": every_detail("counterevidence_complete"),
        "external_authority": False,
        "decision_impact": every_detail("materiality_review_approved"),
        "evidence_complete": evidence_complete,
    }


def _audit_trial_entry(
    entry: Mapping[str, Any],
    *,
    workspace: Path,
    report_finding: Mapping[str, Any],
    suite_id: str,
    manifest_hash: str,
    protocol_digest: str,
) -> tuple[dict[str, Any], bool]:
    checks = {name: False for name in _ENTRY_CHECKS}
    reasons: set[str] = set()
    derived = _false_finding(entry["case_id"])
    public_certificate_audits: list[dict[str, Any]] = []
    internal_certificate_audits: list[dict[str, Any]] = []
    try:
        project = Project.open(workspace)
        run_id = entry["run_id"]
        paths = project.paths(run_id)
        run = project.get_run(run_id)
        validate_or_raise("run", run)
        target = project.get_target(run_id)

        trial = project.validate_trial_binding(run_id)
        if trial is None:
            reasons.add("TRIAL_BINDING_MISSING")
        else:
            preregistration, budget = trial
            binding = run["trial_binding"]
            checks["preregistration_bound"] = all(
                (
                    binding["suite_id"] == suite_id,
                    binding["case_id"] == entry["case_id"],
                    binding["variant"] == entry["variant"],
                    binding["manifest_hash"] == manifest_hash,
                    binding["preregistration_hash"] == entry["preregistration_hash"],
                    preregistration["manifest_hash"] == manifest_hash,
                )
            )
            checks["protocol_and_budget_bound"] = all(
                (
                    run["protocol"]["sha256"] == protocol_digest,
                    preregistration["protocol_hash"] == protocol_digest,
                    protocol_hash(read_json(paths.protocol)) == protocol_digest,
                    run["budget_policy_hash"] == entry["budget_policy_hash"],
                    budget.sha256 == entry["budget_policy_hash"],
                    preregistration["budget_policy_hash"] == entry["budget_policy_hash"],
                )
            )

        snapshot_identity = {
            "commit": target["commit"],
            "tree": target["tree"],
            "submodules": target.get("submodules", []),
            "dependency_locks": target.get("dependency_locks", []),
        }
        checks["run_identity_bound"] = all(
            (
                run["run_id"] == run_id,
                sha256_file(paths.run) == entry["run_sha256"],
                target.get("snapshot_identity") == snapshot_identity,
                target.get("snapshot_hash") == hash_json(snapshot_identity),
                run["target"]["repository_commit"] == target["commit"],
                run["target"]["snapshot_hash"] == target["snapshot_hash"],
                hash_json(read_json(paths.context)) == run["context_manifest_hash"],
                hash_json(read_json(paths.knowledge_boundary)) == run["knowledge_boundary_hash"],
            )
        )

        ledger_report = project.ledger(run_id).verify()
        events = project.ledger(run_id).read_all() if ledger_report.valid else []
        expected_created_payload = {
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "context_manifest_hash": run["context_manifest_hash"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "trial_preregistration_hash": run.get("trial_binding", {}).get("preregistration_hash"),
            "budget_policy_hash": run.get("budget_policy_hash"),
        }
        created_events = [event for event in events if event.get("event_type") == "RUN_CREATED"]
        checks["ledger_head_matches"] = all(
            (
                ledger_report.valid,
                ledger_report.entries == entry["ledger"]["entries"],
                ledger_report.last_hash == entry["ledger"]["last_hash"],
                len(created_events) == 1,
                len(created_events) == 1 and created_events[0].get("sequence") == 0,
                len(created_events) == 1
                and created_events[0].get("payload") == expected_created_payload,
            )
        )

        result_reference = entry["result_ref"]
        if entry["variant"] == AblationVariant.DETERMINISTIC_DETECTORS_ONLY.value:
            store = ArtifactStore(project.artifacts_root)
            digest = result_reference["sha256"]
            result = json.loads(store.read_bytes(digest).decode("utf-8"))
            validate_or_raise("baseline-result", result)
            checks["result_artifact_bound"] = all(
                (
                    result_reference["kind"] == "BASELINE_RESULT",
                    result_reference["storage"] == "CAS",
                    result["run_id"] == run_id,
                    result["snapshot_hash"] == target["snapshot_hash"],
                    result["snapshot_commit"] == target["commit"],
                    result["protocol_hash"] == protocol_digest,
                    _matching_artifact_event(
                        events,
                        event_type="DETERMINISTIC_BASELINE_COMPLETED",
                        digest=digest,
                        expected_payload={
                            "baseline_run_id": result["baseline_run_id"],
                            "signal_count": result["signal_count"],
                            "snapshot_hash": result["snapshot_hash"],
                            "protocol_hash": result["protocol_hash"],
                        },
                    ),
                )
            )
        else:
            expected_mode = _INVESTIGATION_MODES.get(entry["variant"])
            result_path = paths.root / "investigation" / "result.json"
            start_path = paths.root / "investigation" / "start.json"
            result = read_json(result_path)
            start = read_json(start_path)
            validate_or_raise("investigation-result", result)
            result_digest = sha256_file(result_path)
            start_digest = sha256_file(start_path)
            expected_provider = {
                "provider": result["provider"]["provider"],
                "name": result["provider"]["model"],
            }
            checks["result_artifact_bound"] = all(
                (
                    result_reference["kind"] == "INVESTIGATION_RESULT",
                    result_reference["storage"] == "RUN_FILE",
                    result_reference.get("path") == "investigation/result.json",
                    result_reference["sha256"] == result_digest,
                    result["run_id"] == run_id,
                    result["mode"] == expected_mode,
                    result["provenance"]["target_snapshot_hash"] == target["snapshot_hash"],
                    result["provenance"]["protocol_hash"] == protocol_digest,
                    result["provenance"]["budget_policy_hash"] == entry["budget_policy_hash"],
                    hash_json(result["budget"]["limits"]) == entry["budget_policy_hash"],
                    expected_provider == run["model"],
                    start.get("run_id") == run_id,
                    start.get("mode") == expected_mode,
                    start.get("target_snapshot_hash") == target["snapshot_hash"],
                    start.get("protocol_hash") == protocol_digest,
                    start.get("budget_policy_hash") == entry["budget_policy_hash"],
                    start.get("budget_policy") == result["budget"]["limits"],
                    start.get("provider") == result["provider"],
                    _matching_artifact_event(
                        events,
                        event_type="INVESTIGATION_STARTED",
                        digest=start_digest,
                        path="investigation/start.json",
                    ),
                    _matching_artifact_event(
                        events,
                        event_type="INVESTIGATION_COMPLETED",
                        digest=result_digest,
                        path="investigation/result.json",
                    ),
                )
            )

        verified_candidates: set[str] = set()
        for candidate_root in sorted(paths.discoveries.iterdir()):
            candidate_path = candidate_root / "candidate.json"
            if (
                candidate_root.is_symlink()
                or candidate_root.resolve().parent != paths.discoveries.resolve()
                or not candidate_root.is_dir()
                or not candidate_path.is_file()
            ):
                raise IntegrityError(
                    "Trial discoveries contain an unrecognized candidate entry.",
                    details={"path": candidate_root.name},
                )
            candidate = read_json(candidate_path)
            validate_or_raise("candidate", candidate)
            if candidate["candidate_id"] != candidate_root.name or candidate["run_id"] != run_id:
                raise IntegrityError(
                    "Trial candidate directory identity is invalid.",
                    details={"path": candidate_root.name},
                )
            if project.current_state(run_id, candidate["candidate_id"]).value == "VERIFIED":
                verified_candidates.add(candidate["candidate_id"])
        certificate_refs = list(entry["certificate_refs"])
        referenced_candidates = {reference["candidate_id"] for reference in certificate_refs}
        checks["certificate_set_complete"] = referenced_candidates == verified_candidates and len(
            referenced_candidates
        ) == len(certificate_refs)
        for reference in sorted(certificate_refs, key=lambda item: item["candidate_id"]):
            candidate_id = reference["candidate_id"]
            certificate_path = project.candidate_dir(run_id, candidate_id) / "certificate.yaml"
            digest_matches = (
                certificate_path.is_file()
                and sha256_file(certificate_path) == reference["certificate_sha256"]
            )
            failed_checks: list[str] = []
            audit: dict[str, Any] = {}
            try:
                audit = AuthorityKernel(project).audit_certificate(run_id, candidate_id)
                failed_checks = list(audit.get("failed_checks", []))
            except Exception as exc:  # evidence corruption must be reported, not abort the matrix
                failed_checks = [f"CERTIFICATE_AUDIT_{type(exc).__name__.upper()}"]
            valid = digest_matches and audit.get("valid") is True
            if not digest_matches:
                failed_checks.append("certificate_sha256")
            public_certificate_audits.append(
                {
                    "candidate_id": candidate_id,
                    "certificate_sha256": reference["certificate_sha256"],
                    "valid": valid,
                    "failed_checks": sorted(set(failed_checks)),
                }
            )
            internal_certificate_audits.append({**audit, **public_certificate_audits[-1]})
        checks["certificate_graphs_valid"] = checks["certificate_set_complete"] and all(
            audit["valid"] for audit in public_certificate_audits
        )
        derived = _derive_verified_finding(
            entry["case_id"],
            internal_certificate_audits,
            actual_verified=bool(verified_candidates),
            certificate_set_complete=checks["certificate_set_complete"],
        )
    except Exception as exc:  # one damaged evidence bundle must not hide the rest of the matrix
        reasons.add(f"ENTRY_EVIDENCE_{type(exc).__name__.upper()}")

    for name, passed in checks.items():
        if not passed:
            reasons.add(f"{name.upper()}_FAILED")
    finding_matches = canonical_json(derived) == canonical_json(report_finding)
    if not finding_matches:
        reasons.add("FINDING_FLAGS_MISMATCH")
    entry_passed = all(checks.values()) and finding_matches
    return (
        {
            "variant": entry["variant"],
            "case_id": entry["case_id"],
            "run_id": entry["run_id"],
            "audit_result": "PASS" if entry_passed else "FAIL",
            "checks": checks,
            "derived_finding": derived,
            "certificate_audits": public_certificate_audits,
            "reason_codes": sorted(reasons),
        },
        finding_matches,
    )


def audit_trial_evidence(
    report: dict[str, Any],
    evidence_index: dict[str, Any],
    *,
    base_path: Path,
) -> dict[str, Any]:
    """Structurally audit every trial finding against its preregistered run evidence.

    This legacy structural PASS is deliberately non-certifying and cannot substitute for
    the v0.4 authenticated custody, isolation, certificate, and checkpoint verification path.
    """

    report_value = dict(_mapping(_json_safe(report), "report"))
    index_value = dict(_mapping(_json_safe(evidence_index), "evidence_index"))
    validate_or_raise("trial-report", report_value)
    validate_or_raise("trial-evidence-index", index_value)
    report_hash = _verify_self_hash(report_value, "report_hash", "Trial report")
    index_hash = _verify_self_hash(index_value, "index_hash", "Trial evidence index")

    rebuilt = aggregate_trials(
        dict(_mapping(report_value["manifest"], "report.manifest")),
        list(_sequence(report_value["variant_results"], "report.variant_results")),
    )
    if canonical_json(rebuilt) != canonical_json(report_value):
        raise IntegrityError("Trial report does not match deterministic recomputation.")
    recomputed_report_hash = rebuilt["report_hash"]

    protocol_hashes = {result["protocol_hash"] for result in rebuilt["variant_results"]}
    index_binding_valid = all(
        (
            index_value["suite_id"] == rebuilt["suite_id"],
            index_value["manifest_hash"] == rebuilt["manifest_hash"],
            index_value["report_hash"] == report_hash,
            protocol_hashes == {index_value["protocol_hash"]},
        )
    )

    findings_by_key = {
        (result["variant"], finding["case_id"]): finding
        for result in rebuilt["variant_results"]
        for finding in result["findings"]
    }
    entries = list(index_value["entries"])
    workspace_paths = _safe_workspace_paths(entries, base_path)
    entry_keys = [(entry["variant"], entry["case_id"]) for entry in entries]
    run_locations = [
        (str(workspace_paths[key]), entry["run_id"])
        for key, entry in zip(entry_keys, entries, strict=True)
    ]
    index_coverage_complete = all(
        (
            set(entry_keys) == set(findings_by_key),
            len(entry_keys) == len(set(entry_keys)),
            len(run_locations) == len(set(run_locations)),
        )
    )

    entry_audits: list[dict[str, Any]] = []
    finding_matches: list[bool] = []
    for entry in sorted(entries, key=lambda item: (item["variant"], item["case_id"])):
        key = (entry["variant"], entry["case_id"])
        report_finding = findings_by_key.get(key, _false_finding(entry["case_id"]))
        audit, matches = _audit_trial_entry(
            entry,
            workspace=workspace_paths[key],
            report_finding=report_finding,
            suite_id=rebuilt["suite_id"],
            manifest_hash=rebuilt["manifest_hash"],
            protocol_digest=index_value["protocol_hash"],
        )
        entry_audits.append(audit)
        finding_matches.append(matches and key in findings_by_key)

    def all_entries(check: str) -> bool:
        return bool(entry_audits) and all(
            entry["checks"].get(check) is True for entry in entry_audits
        )

    structural_checks = {
        "report_recomputed": True,
        "index_binding_valid": index_binding_valid,
        "index_coverage_complete": index_coverage_complete,
        "preregistration_bound": all_entries("preregistration_bound"),
        "run_identity_bound": all_entries("run_identity_bound"),
        "protocol_and_budget_bound": all_entries("protocol_and_budget_bound"),
        "ledger_heads_match": all_entries("ledger_head_matches"),
        "result_artifacts_bound": all_entries("result_artifact_bound"),
        "certificate_graphs_valid": all_entries("certificate_graphs_valid"),
        "finding_flags_match_evidence": (
            index_coverage_complete and bool(finding_matches) and all(finding_matches)
        ),
    }
    audit_result = "PASS" if all(structural_checks.values()) else "FAIL"
    reasons = set(_CERTIFICATION_BLOCKERS)
    reasons.update(
        f"STRUCTURAL_{name.upper()}_FAILED"
        for name, passed in structural_checks.items()
        if not passed
    )
    reasons.update(reason for entry in entry_audits for reason in entry["reason_codes"])
    audit: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "audit_type": "M0_TRIAL_EVIDENCE_AUDIT",
        "suite_id": rebuilt["suite_id"],
        "manifest_hash": rebuilt["manifest_hash"],
        "protocol_hash": index_value["protocol_hash"],
        "report_hash": report_hash,
        "evidence_index_hash": index_hash,
        "recomputed_report_hash": recomputed_report_hash,
        "audit_result": audit_result,
        "structural_checks": structural_checks,
        "authorization_checks": {name: False for name in _AUTHORIZATION_CHECKS},
        "certification_blockers": sorted(_CERTIFICATION_BLOCKERS),
        "entries": entry_audits,
        "status": "NON_CERTIFYING",
        "m0_demonstrated": False,
        "reason_codes": sorted(reasons),
    }
    audit["audit_hash"] = hash_json(audit)
    validate_or_raise("trial-evidence-audit", audit)
    return audit


def _strict_document(raw: bytes, schema_name: str, label: str) -> dict[str, Any]:
    value = parse_strict_json(raw)
    if not isinstance(value, dict):
        raise UsageError(f"{label} must be a strict JSON object.")
    validate_or_raise(schema_name, value)
    return value


def _safe_matrix_file(base_path: Path, locator: str, expected_sha256: str) -> bytes:
    """Read one matrix-relative regular file without crossing links or mount aliases."""

    if not isinstance(locator, str) or not locator:
        raise UsageError("Trial matrix file locators must be non-empty strings.")
    posix = PurePosixPath(locator)
    windows = PureWindowsPath(locator)
    if any(
        (
            posix.is_absolute(),
            bool(posix.root),
            ".." in posix.parts,
            windows.is_absolute(),
            bool(windows.drive),
            bool(windows.root),
            ".." in windows.parts,
        )
    ):
        raise UsageError("Trial matrix file locators must be safe relative paths.")
    base = base_path.expanduser().resolve()
    candidate = base.joinpath(*posix.parts)
    cursor = base
    for part in posix.parts:
        cursor /= part
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            raise IntegrityError(
                "Trial matrix evidence file is missing.", details={"path": locator}
            ) from exc
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
            raise UsageError("Trial matrix evidence paths cannot contain links or reparse points.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise IntegrityError(
            "Trial matrix evidence file is missing.", details={"path": locator}
        ) from exc
    if resolved != base and base not in resolved.parents:
        raise UsageError("Trial matrix evidence file resolves outside the matrix directory.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise IntegrityError(
            "Trial matrix evidence file could not be opened safely.", details={"path": locator}
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UsageError("Trial matrix evidence locators must identify regular files.")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise IntegrityError("Trial matrix evidence changed during exact-byte read.")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if sha256_bytes(raw) != expected_sha256:
        raise IntegrityError("Trial matrix evidence hash mismatch.", details={"path": locator})
    return raw


def _matrix_relative_workspace(base_path: Path, locator: str) -> Path:
    if not isinstance(locator, str) or not locator:
        raise UsageError("Trial matrix workspace locators must be non-empty strings.")
    native = Path(locator)
    posix = PurePosixPath(locator)
    windows = PureWindowsPath(locator)
    if any(
        (
            native.is_absolute(),
            bool(native.drive),
            posix.is_absolute(),
            bool(posix.root),
            ".." in posix.parts,
            windows.is_absolute(),
            bool(windows.drive),
            bool(windows.root),
            ".." in windows.parts,
        )
    ):
        raise UsageError("Trial matrix workspaces must be safe relative paths.")
    base = base_path.expanduser().resolve()
    cursor = base
    for part in native.parts:
        cursor /= part
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            raise IntegrityError(
                "Trial matrix workspace is missing.", details={"workspace": locator}
            ) from exc
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
            raise UsageError("Trial matrix workspace cannot contain links or reparse points.")
    try:
        candidate = (base / native).resolve(strict=True)
    except OSError as exc:
        raise IntegrityError(
            "Trial matrix workspace changed during validation.", details={"workspace": locator}
        ) from exc
    if candidate != base and base not in candidate.parents:
        raise UsageError("Trial matrix workspace escapes the matrix directory.")
    if not candidate.is_dir():
        raise UsageError("Trial matrix workspace must identify a directory.")
    return candidate


def _certificate_set_sha256(bindings: Sequence[Mapping[str, Any]]) -> str:
    return hash_json(
        [
            {
                "candidate_id": binding["candidate_id"],
                "authority_envelope_sha256": binding["authority_envelope"]["sha256"],
                "c_pre_checkpoint_envelope_sha256": binding["c_pre_checkpoint_envelope"]["sha256"],
            }
            for binding in sorted(bindings, key=lambda item: item["candidate_id"])
        ]
    )


def _verify_matrix_run_result(
    entry: Mapping[str, Any],
    indexed: Mapping[str, Any],
    *,
    project: Project,
    run: Mapping[str, Any],
    target: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    result_bytes: bytes,
    protocol_digest: str,
) -> None:
    """Bind the signed matrix result to the actual run artifact and completion event."""

    reference = indexed["result_ref"]
    if reference["sha256"] != entry["result"]["sha256"]:
        raise IntegrityError("Matrix and evidence index result hashes do not match.")
    result = parse_strict_json(result_bytes)
    if not isinstance(result, dict):
        raise UsageError("Trial matrix result must be a strict JSON object.")
    run_id = entry["run_id"]
    if entry["variant"] == AblationVariant.DETERMINISTIC_DETECTORS_ONLY.value:
        if reference != {
            "kind": "BASELINE_RESULT",
            "storage": "CAS",
            "sha256": entry["result"]["sha256"],
        }:
            raise IntegrityError("Deterministic matrix result has an invalid index reference.")
        validate_or_raise("baseline-result", result)
        store = ArtifactStore(project.artifacts_root)
        store.verify_or_raise(reference["sha256"])
        if store.read_bytes(reference["sha256"]) != result_bytes:
            raise IntegrityError("Baseline matrix result is not the exact run CAS artifact.")
        if not all(
            (
                result["run_id"] == run_id,
                result["snapshot_hash"] == target["snapshot_hash"],
                result["snapshot_commit"] == target["commit"],
                result["protocol_hash"] == protocol_digest,
                _matching_artifact_event(
                    events,
                    event_type="DETERMINISTIC_BASELINE_COMPLETED",
                    digest=reference["sha256"],
                    expected_payload={
                        "baseline_run_id": result["baseline_run_id"],
                        "signal_count": result["signal_count"],
                        "snapshot_hash": result["snapshot_hash"],
                        "protocol_hash": result["protocol_hash"],
                    },
                ),
            )
        ):
            raise IntegrityError("Baseline matrix result is not bound to its run and ledger.")
        return

    expected_mode = _INVESTIGATION_MODES[entry["variant"]]
    if reference != {
        "kind": "INVESTIGATION_RESULT",
        "storage": "RUN_FILE",
        "sha256": entry["result"]["sha256"],
        "path": "investigation/result.json",
    }:
        raise IntegrityError("Investigation matrix result has an invalid index reference.")
    validate_or_raise("investigation-result", result)
    paths = project.paths(run_id)
    actual_result_path = paths.root / "investigation" / "result.json"
    actual_result_bytes = actual_result_path.read_bytes()
    if (
        actual_result_bytes != result_bytes
        or sha256_bytes(actual_result_bytes) != reference["sha256"]
    ):
        raise IntegrityError("Investigation matrix result is not the exact run result file.")
    start_path = paths.root / "investigation" / "start.json"
    start_bytes = start_path.read_bytes()
    start = parse_strict_json(start_bytes)
    if not isinstance(start, dict):
        raise UsageError("Investigation start record must be a strict JSON object.")
    budget_hash = run["budget_policy_hash"]
    expected_provider = {
        "provider": result["provider"]["provider"],
        "name": result["provider"]["model"],
    }
    if not all(
        (
            result["run_id"] == run_id,
            result["mode"] == expected_mode,
            result["provenance"]["target_snapshot_hash"] == target["snapshot_hash"],
            result["provenance"]["protocol_hash"] == protocol_digest,
            result["provenance"]["budget_policy_hash"] == budget_hash,
            hash_json(result["budget"]["limits"]) == budget_hash,
            expected_provider == run["model"],
            start.get("run_id") == run_id,
            start.get("mode") == expected_mode,
            start.get("target_snapshot_hash") == target["snapshot_hash"],
            start.get("protocol_hash") == protocol_digest,
            start.get("budget_policy_hash") == budget_hash,
            start.get("budget_policy") == result["budget"]["limits"],
            start.get("provider") == result["provider"],
            _matching_artifact_event(
                events,
                event_type="INVESTIGATION_STARTED",
                digest=sha256_bytes(start_bytes),
                path="investigation/start.json",
            ),
            _matching_artifact_event(
                events,
                event_type="INVESTIGATION_COMPLETED",
                digest=reference["sha256"],
                path="investigation/result.json",
            ),
        )
    ):
        raise IntegrityError("Investigation matrix result is not bound to its frozen run inputs.")


def certify_m0_v2(
    certification_envelope_bytes: bytes,
    trial_evaluation_envelope_bytes: bytes,
    *,
    trust_policy_bytes: bytes,
    trust_policy_sha256: str,
    manifest_bytes: bytes,
    custody_envelope_bytes: bytes,
    report_bytes: bytes,
    evidence_index_bytes: bytes,
    audit_bytes: bytes,
    run_matrix_bytes: bytes,
    base_path: Path,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Authenticate a complete v0.4 5x7 M0 matrix without trusting producer flags."""

    manifest = _strict_document(manifest_bytes, "trial-manifest", "Trial manifest")
    report = _strict_document(report_bytes, "trial-report", "Trial report")
    evidence_index = _strict_document(
        evidence_index_bytes, "trial-evidence-index", "Trial evidence index"
    )
    audit = _strict_document(audit_bytes, "trial-evidence-audit", "Trial evidence audit")
    matrix = _strict_document(run_matrix_bytes, "trial-run-matrix", "Trial run matrix")
    report_hash = _verify_self_hash(report, "report_hash", "Trial report")
    index_hash = _verify_self_hash(evidence_index, "index_hash", "Trial evidence index")
    audit_hash = _verify_self_hash(audit, "audit_hash", "Trial evidence audit")
    matrix_hash = _verify_self_hash(matrix, "matrix_sha256", "Trial run matrix")
    rebuilt = aggregate_trials(report["manifest"], report["variant_results"])
    if canonical_json(rebuilt) != canonical_json(report):
        raise IntegrityError("Trial report does not match deterministic recomputation.")
    manifest_sha256 = sha256_bytes(manifest_bytes)
    protocol_hashes = {item["protocol_hash"] for item in report["variant_results"]}
    if len(protocol_hashes) != 1:
        raise IntegrityError("Trial report does not bind one protocol hash.")
    protocol_digest = next(iter(protocol_hashes))
    if not all(
        (
            manifest == report["manifest"],
            matrix["suite_id"] == report["suite_id"] == audit["suite_id"],
            matrix["manifest_sha256"] == manifest_sha256,
            matrix["protocol_hash"] == protocol_digest == audit["protocol_hash"],
            evidence_index["suite_id"] == report["suite_id"],
            evidence_index["manifest_hash"] == report["manifest_hash"],
            evidence_index["protocol_hash"] == protocol_digest,
            evidence_index["report_hash"] == report_hash,
            audit["manifest_hash"] == report["manifest_hash"],
            audit["report_hash"] == report_hash,
            audit["evidence_index_hash"] == index_hash,
            audit["recomputed_report_hash"] == report_hash,
        )
    ):
        raise IntegrityError("M0 v2 top-level evidence bindings are inconsistent.")

    case_items = list(manifest["cases"])
    cases = {item["case_id"]: item for item in case_items}
    positive_count = sum(item["kind"] == "POSITIVE" for item in case_items)
    control_count = sum(item["kind"] == "CONTROL" for item in case_items)
    manifest_gate_names = (
        "case_mix_exact",
        "benchmark_sealed",
        "independent_custody",
        "sealed_before_explorer",
    )
    if any(
        (
            len(case_items) != 7,
            len(cases) != 7,
            positive_count != 5,
            control_count != 2,
            not all(report["gates"].get(name) is True for name in manifest_gate_names),
        )
    ):
        raise IntegrityError("M0 manifest is not the exact sealed 5-positive/2-control case mix.")
    entries = list(matrix["entries"])
    pairs = {(entry["variant"], entry["case_id"]) for entry in entries}
    expected_pairs = {(variant, case_id) for variant in ABLATION_VARIANTS for case_id in cases}
    workspaces = [_matrix_relative_workspace(base_path, entry["workspace"]) for entry in entries]
    if any(
        (
            len(cases) != 7,
            len(entries) != 35,
            pairs != expected_pairs,
            len(pairs) != 35,
            len({entry["run_id"] for entry in entries}) != 35,
            len(set(workspaces)) != 35,
        )
    ):
        raise IntegrityError("Trial run matrix is not one unique 5x7 Cartesian run set.")

    verified_custody = verify_custody_attestation(
        custody_envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        manifest_bytes=manifest_bytes,
        expected_suite_id=matrix["suite_id"],
        expected_manifest_sha256=manifest_sha256,
        now=now,
    )
    findings = {
        (variant_result["variant"], finding["case_id"]): finding
        for variant_result in report["variant_results"]
        for finding in variant_result["findings"]
    }
    raw_index_entries = list(evidence_index["entries"])
    index_keys = [(entry["variant"], entry["case_id"]) for entry in raw_index_entries]
    index_run_locations = [(entry["workspace"], entry["run_id"]) for entry in raw_index_entries]
    if any(
        (
            len(raw_index_entries) != 35,
            len(set(index_keys)) != 35,
            set(index_keys) != expected_pairs,
            len(set(index_run_locations)) != 35,
        )
    ):
        raise IntegrityError("Trial evidence index is not one exact unique 5x7 run matrix.")
    index_entries = {(entry["variant"], entry["case_id"]): entry for entry in raw_index_entries}
    derived: dict[tuple[str, str], dict[str, Any]] = {}
    run_bindings: list[dict[str, Any]] = []
    certificate_graphs_valid = True
    isolation_attestations_authenticated = True
    ledger_checkpoints_authenticated = True
    for entry, workspace in sorted(
        zip(entries, workspaces, strict=True),
        key=lambda pair: (pair[0]["variant"], pair[0]["case_id"]),
    ):
        key = (entry["variant"], entry["case_id"])
        indexed = index_entries.get(key)
        if indexed is None or indexed["run_id"] != entry["run_id"]:
            raise IntegrityError("Trial matrix entry is not covered by the evidence index.")
        project = Project.open(workspace)
        run = project.get_run(entry["run_id"])
        target = project.get_target(entry["run_id"])
        trial = project.validate_trial_binding(entry["run_id"])
        if trial is None:
            raise IntegrityError("Trial matrix run lacks its immutable preregistration binding.")
        preregistration, budget = trial
        run_binding = run["trial_binding"]
        if not all(
            (
                indexed["workspace"] == entry["workspace"],
                run["run_id"] == indexed["run_id"] == entry["run_id"],
                sha256_file(project.paths(entry["run_id"]).run) == indexed["run_sha256"],
                run_binding["suite_id"] == matrix["suite_id"],
                run_binding["case_id"] == entry["case_id"],
                run_binding["variant"] == entry["variant"],
                run_binding["manifest_hash"] == report["manifest_hash"],
                run_binding["preregistration_hash"] == indexed["preregistration_hash"],
                preregistration["manifest_hash"] == report["manifest_hash"],
                preregistration["protocol_hash"] == protocol_digest,
                preregistration["budget_policy_hash"] == indexed["budget_policy_hash"],
                run["budget_policy_hash"] == budget.sha256 == indexed["budget_policy_hash"],
                run["protocol"]["sha256"] == protocol_digest,
            )
        ):
            raise IntegrityError("Trial matrix run and evidence-index bindings are inconsistent.")
        result_bytes = _safe_matrix_file(
            base_path, entry["result"]["path"], entry["result"]["sha256"]
        )
        ledger_bytes = _safe_matrix_file(
            base_path, entry["ledger"]["path"], entry["ledger"]["sha256"]
        )
        if ledger_bytes != project.paths(entry["run_id"]).ledger.read_bytes():
            raise IntegrityError("Signed final ledger is not the current project ledger bytes.")
        ledger_report = project.ledger(entry["run_id"]).verify(raise_on_error=True)
        if (
            indexed["ledger"]["entries"] != ledger_report.entries
            or indexed["ledger"]["last_hash"] != ledger_report.last_hash
        ):
            raise IntegrityError(
                "Evidence index ledger head does not match the signed final ledger."
            )
        _verify_matrix_run_result(
            entry,
            indexed,
            project=project,
            run=run,
            target=target,
            events=project.ledger(entry["run_id"]).read_all(),
            result_bytes=result_bytes,
            protocol_digest=protocol_digest,
        )
        isolation_bytes = _safe_matrix_file(
            base_path, entry["isolation_envelope"]["path"], entry["isolation_envelope"]["sha256"]
        )
        final_checkpoint_bytes = _safe_matrix_file(
            base_path,
            entry["final_checkpoint_envelope"]["path"],
            entry["final_checkpoint_envelope"]["sha256"],
        )
        isolation = verify_isolation_attestation(
            isolation_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            result_bytes=result_bytes,
            expected_suite_id=matrix["suite_id"],
            expected_case_id=entry["case_id"],
            expected_variant=entry["variant"],
            expected_run_id=entry["run_id"],
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=protocol_digest,
            now=now,
        )
        final_checkpoint = verify_ledger_checkpoint(
            final_checkpoint_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            ledger_bytes=ledger_bytes,
            expected_suite_id=matrix["suite_id"],
            expected_case_id=entry["case_id"],
            expected_variant=entry["variant"],
            expected_run_id=entry["run_id"],
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=protocol_digest,
            now=now,
        )
        certificate_audits: list[dict[str, Any]] = []
        indexed_certificates = {item["candidate_id"]: item for item in indexed["certificate_refs"]}
        for certificate_binding in entry["certificate_bindings"]:
            authority_bytes = _safe_matrix_file(
                base_path,
                certificate_binding["authority_envelope"]["path"],
                certificate_binding["authority_envelope"]["sha256"],
            )
            c_pre_bytes = _safe_matrix_file(
                base_path,
                certificate_binding["c_pre_checkpoint_envelope"]["path"],
                certificate_binding["c_pre_checkpoint_envelope"]["sha256"],
            )
            verdict = read_json(
                project.candidate_dir(entry["run_id"], certificate_binding["candidate_id"])
                / "verdict.json"
            )
            authority_data = verdict["authority_actor"]
            authority = Actor(authority_data["actor_id"], authority_data["role"])
            certificate_audit = AuthorityKernel(project).audit_certificate_v2(
                entry["run_id"],
                certificate_binding["candidate_id"],
                authority=authority,
                authority_envelope_bytes=authority_bytes,
                checkpoint_envelope_bytes=c_pre_bytes,
                custody_envelope_bytes=custody_envelope_bytes,
                isolation_envelope_bytes=isolation_bytes,
                trust_policy_bytes=trust_policy_bytes,
                trust_policy_sha256=trust_policy_sha256,
                manifest_bytes=manifest_bytes,
                isolation_result_bytes=result_bytes,
                now=now,
            )
            indexed_certificate = indexed_certificates.get(certificate_binding["candidate_id"])
            if (
                indexed_certificate is None
                or certificate_audit.get("certificate_sha256")
                != indexed_certificate["certificate_sha256"]
            ):
                raise IntegrityError(
                    "Evidence index certificate digest does not match the v2 certificate audit."
                )
            certificate_audits.append(certificate_audit)
        expected_certificate_ids = {item["candidate_id"] for item in indexed["certificate_refs"]}
        matrix_certificate_ids = {item["candidate_id"] for item in entry["certificate_bindings"]}
        if len(expected_certificate_ids) != len(indexed["certificate_refs"]) or len(
            matrix_certificate_ids
        ) != len(entry["certificate_bindings"]):
            raise IntegrityError("Trial certificate bindings contain duplicate candidate IDs.")
        committed_candidate_ids: set[str] = set()
        for candidate_root in project.paths(entry["run_id"]).discoveries.iterdir():
            if candidate_root.is_symlink() or not candidate_root.is_dir():
                raise IntegrityError("Trial discoveries contain an unsafe candidate entry.")
            if (candidate_root / "authorization-commit.json").is_file():
                committed_candidate_ids.add(candidate_root.name)
        complete = expected_certificate_ids == matrix_certificate_ids == committed_candidate_ids
        if not complete:
            raise IntegrityError(
                "Matrix, index, and authorization marker candidate sets do not match exactly."
            )
        actual_verified = bool(matrix_certificate_ids)
        committed_events = [
            event
            for event in project.ledger(entry["run_id"]).read_all()
            if event.get("event_type") == "AUTHORIZATION_COMMITTED"
        ]
        committed_ids = {event.get("payload", {}).get("candidate_id") for event in committed_events}
        if matrix_certificate_ids != committed_ids or len(committed_events) != len(committed_ids):
            raise IntegrityError(
                "Final authenticated checkpoint does not exactly cover authorization markers."
            )
        derived[key] = _derive_verified_finding(
            entry["case_id"],
            certificate_audits,
            actual_verified=actual_verified,
            certificate_set_complete=complete,
        )
        if actual_verified:
            derived[key]["external_authority"] = all(
                item.get("valid") is True for item in certificate_audits
            )
        certificate_graphs_valid &= complete and all(
            item.get("valid") is True for item in certificate_audits
        )
        run_bindings.append(
            {
                "variant": entry["variant"],
                "case_id": entry["case_id"],
                "run_id": entry["run_id"],
                "target_snapshot_hash": target["snapshot_hash"],
                "result_sha256": entry["result"]["sha256"],
                "isolation_envelope_sha256": entry["isolation_envelope"]["sha256"],
                "ledger_checkpoint_envelope_sha256": entry["final_checkpoint_envelope"]["sha256"],
                "evidence_index_entry_sha256": hash_json(indexed),
                "certificate_set_sha256": _certificate_set_sha256(entry["certificate_bindings"]),
            }
        )
        if not isolation.production_qualified or not final_checkpoint.production_qualified:
            certificate_graphs_valid = False
        isolation_attestations_authenticated &= isolation.production_qualified
        ledger_checkpoints_authenticated &= final_checkpoint.production_qualified

    if any(canonical_json(derived[key]) != canonical_json(findings[key]) for key in expected_pairs):
        raise IntegrityError("Authenticated M0 findings do not match the deterministic report.")
    evaluation = verify_trial_evaluation(
        trial_evaluation_envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        custody_envelope_bytes=custody_envelope_bytes,
        report_bytes=report_bytes,
        evidence_index_bytes=evidence_index_bytes,
        audit_bytes=audit_bytes,
        run_matrix_bytes=run_matrix_bytes,
        expected_suite_id=matrix["suite_id"],
        expected_manifest_sha256=manifest_sha256,
        expected_protocol_hash=protocol_digest,
        expected_run_bindings=run_bindings,
        now=now,
    )
    full_findings = [derived[(FULL_SYSTEM_VARIANT, case_id)] for case_id in sorted(cases)]
    claimed = [
        finding for finding in full_findings if finding["claimed_verified"] or finding["verified"]
    ]
    trusted = [
        finding
        for finding in full_findings
        if _trusted_positive(finding, cases[finding["case_id"]]["kind"])
    ]
    false_claims = [
        finding
        for finding in claimed
        if not _trusted_positive(finding, cases[finding["case_id"]]["kind"])
    ]
    false_controls = [
        finding for finding in claimed if cases[finding["case_id"]]["kind"] == "CONTROL"
    ]
    clean_replay = [finding for finding in claimed if finding["replay_passed"]]
    context_complete = bool(claimed) and all(finding["evidence_complete"] for finding in claimed)
    production_mode = evaluation.trust_mode == "PRODUCTION"
    expected_observed = {
        "trusted_verified_positives": len(trusted),
        "false_verified_controls": len(false_controls),
        "false_verified_claims": len(false_claims),
        "claimed_verified_total": len(claimed),
        "clean_replay_verified": len(clean_replay),
        "context_provenance_complete": context_complete,
        "target_snapshot_immutable": True,
        "hidden_inputs_immutable": verified_custody.production_qualified,
        "scoring_policy_immutable": True,
    }
    expected_gates = {
        "matrix_complete": True,
        "independent_custody": verified_custody.production_qualified,
        "sealed_before_explorer": verified_custody.production_qualified,
        "actor_identities_authenticated": production_mode,
        "isolation_attestations_authenticated": isolation_attestations_authenticated,
        "ledger_checkpoints_authenticated": ledger_checkpoints_authenticated,
        "certificate_graphs_valid": production_mode and certificate_graphs_valid,
        "positive_threshold_met": len(trusted) >= 3,
        "control_threshold_met": not false_controls and not false_claims,
        "clean_replay_complete": len(clean_replay) == len(claimed) and not false_claims,
        "context_provenance_complete": context_complete,
        "inputs_immutable": verified_custody.production_qualified,
    }
    if (
        evaluation.predicate["observed"] != expected_observed
        or evaluation.predicate["gates"] != expected_gates
    ):
        raise IntegrityError(
            "Signed trial evaluation does not match authenticated v2 findings and gates."
        )
    certification = verify_m0_certification(
        certification_envelope_bytes,
        trust_policy_bytes=trust_policy_bytes,
        trust_policy_sha256=trust_policy_sha256,
        manifest_bytes=manifest_bytes,
        custody_envelope_bytes=custody_envelope_bytes,
        trial_evaluation_envelope_bytes=trial_evaluation_envelope_bytes,
        report_bytes=report_bytes,
        evidence_index_bytes=evidence_index_bytes,
        audit_bytes=audit_bytes,
        run_matrix_bytes=run_matrix_bytes,
        expected_suite_id=matrix["suite_id"],
        expected_manifest_sha256=manifest_sha256,
        expected_protocol_hash=protocol_digest,
        expected_run_bindings=run_bindings,
        now=now,
    )
    demonstrated = bool(
        certification.demonstrated
        and evaluation.production_qualified
        and certificate_graphs_valid
        and evaluation.predicate["status"] == "THRESHOLDS_MET"
    )
    if certification.statement.predicate["decision"] == "M0_DEMONSTRATED" and not demonstrated:
        raise IntegrityError("Signed M0_DEMONSTRATED claim does not match authenticated gates.")
    return {
        "status": "M0_DEMONSTRATED" if demonstrated else "M0_NOT_DEMONSTRATED",
        "m0_demonstrated": demonstrated,
        "claim": certification.statement.predicate["claim"],
        "legacy_structural_audit_authoritative": False,
        "authenticated_v2_audit": True,
        "suite_id": matrix["suite_id"],
        "trust_policy_sha256": trust_policy_sha256,
        "manifest_sha256": manifest_sha256,
        "report_sha256": sha256_bytes(report_bytes),
        "evidence_index_sha256": sha256_bytes(evidence_index_bytes),
        "audit_sha256": sha256_bytes(audit_bytes),
        "run_matrix_sha256": sha256_bytes(run_matrix_bytes),
        "run_matrix_self_hash": matrix_hash,
        "trial_evaluation_envelope_sha256": sha256_bytes(trial_evaluation_envelope_bytes),
        "certification_envelope_sha256": sha256_bytes(certification_envelope_bytes),
        "legacy_report_hash": report_hash,
        "legacy_evidence_index_hash": index_hash,
        "legacy_audit_hash": audit_hash,
    }


__all__ = [
    "ABLATION_VARIANTS",
    "FULL_SYSTEM_VARIANT",
    "METRIC_QUANTUM",
    "AblationVariant",
    "aggregate_trials",
    "audit_trial_evidence",
    "certify_m0",
    "certify_m0_v2",
    "manifest_digest",
]
