"""Deterministic M0 trial aggregation and fail-closed certification.

The aggregator is deliberately useful before a benchmark has valid custody: it
can compare ablations and calculate metrics, but labels that output
``NON_CERTIFYING``.  Version 0.2 can calculate the charter's aggregate thresholds,
but it cannot authenticate a custodian or verify each external certificate/CAS/
ledger bundle.  It therefore never emits an M0 success claim.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from enum import StrEnum
from typing import Any

from unasked.errors import IntegrityError, PolicyError, UsageError
from unasked.util import canonical_json, hash_json

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
_CERTIFICATION_GATES = (
    "benchmark_sealed",
    "independent_custody",
    "sealed_before_explorer",
    "case_mix_exact",
    "ablation_coverage_complete",
    "manifest_binding_complete",
    "protocol_frozen",
    "full_system_case_coverage",
    "positive_threshold_met",
    "control_threshold_met",
    "clean_replay_complete",
    "context_provenance_complete",
    "no_false_verified_claims",
    "external_evidence_verified",
)


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
    demonstrated = all(gates[name] for name in _CERTIFICATION_GATES)

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
        "status": "M0_DEMONSTRATED" if demonstrated else "NON_CERTIFYING",
        "m0_demonstrated": demonstrated,
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


__all__ = [
    "ABLATION_VARIANTS",
    "FULL_SYSTEM_VARIANT",
    "METRIC_QUANTUM",
    "AblationVariant",
    "aggregate_trials",
    "certify_m0",
    "manifest_digest",
]
