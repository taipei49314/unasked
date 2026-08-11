from __future__ import annotations

from copy import deepcopy
from decimal import Decimal

import pytest

from unasked.errors import IntegrityError, PolicyError
from unasked.trials import (
    ABLATION_VARIANTS,
    FULL_SYSTEM_VARIANT,
    aggregate_trials,
    certify_m0,
    manifest_digest,
)
from unasked.util import hash_json

PROTOCOL_HASH = "a" * 64


def _manifest(*, sealed: bool = True, positive_count: int = 5) -> dict:
    cases = [
        {
            "case_id": f"P-{number}",
            "kind": "POSITIVE",
            "impact_weight": Decimal(number),
        }
        for number in range(1, positive_count + 1)
    ]
    cases.extend(
        {
            "case_id": f"C-{number}",
            "kind": "CONTROL",
            "impact_weight": Decimal(0),
        }
        for number in range(1, 3)
    )
    return {
        "suite_id": "M0-SUITE-1",
        "cases": cases,
        "custody": {
            "status": "SEALED" if sealed else "UNSEALED",
            "independent": sealed,
            "sealed_before_explorer": sealed,
        },
    }


def _finding(case: dict, *, trusted: bool = False) -> dict:
    return {
        "case_id": case["case_id"],
        "claimed_verified": trusted,
        "verified": trusted,
        "unasked": trusted,
        "novel": trusted,
        "replay_passed": trusted,
        "counterevidence_passed": trusted,
        "external_authority": trusted,
        "decision_impact": trusted,
        "evidence_complete": trusted,
    }


def _results(manifest: dict, *, budget: str | Decimal = "4") -> list[dict]:
    digest = manifest_digest(manifest)
    results = []
    for variant in ABLATION_VARIANTS:
        findings = [
            _finding(
                case,
                trusted=variant == FULL_SYSTEM_VARIANT
                and case["kind"] == "POSITIVE"
                and case["case_id"] in {"P-1", "P-2", "P-3"},
            )
            for case in manifest["cases"]
        ]
        results.append(
            {
                "variant": variant,
                "manifest_hash": digest,
                "protocol_hash": PROTOCOL_HASH,
                "normalized_budget": budget,
                "findings": findings,
            }
        )
    return results


def _full_variant(report: dict) -> dict:
    return next(
        item for item in report["variant_reports"] if item["variant"] == FULL_SYSTEM_VARIANT
    )


def test_sealed_thresholds_are_computed_but_cannot_self_certify_m0() -> None:
    manifest = _manifest()
    report = aggregate_trials(manifest, _results(manifest))

    assert report["status"] == "NON_CERTIFYING"
    assert report["m0_demonstrated"] is False
    assert report["gates"]["external_evidence_verified"] is False
    assert all(
        passed for gate, passed in report["gates"].items() if gate != "external_evidence_verified"
    )
    with pytest.raises(PolicyError, match="external custody"):
        certify_m0(report)

    full = _full_variant(report)
    assert full["counts"] == {
        "cases": 7,
        "positive_cases": 5,
        "control_cases": 2,
        "findings": 7,
        "claimed_verified": 3,
        "trusted_verified_positives": 3,
        "false_verified_claims": 0,
        "false_verified_controls": 0,
    }
    assert full["metrics"] == {
        "trusted_discovery_precision": "1.000000",
        "hidden_discovery_recall": "0.600000",
        "control_false_positive_rate": "0.000000",
        "false_verified_claim_rate": "0.000000",
        "clean_reproduction_rate": "1.000000",
        "decision_impact_rate": "1.000000",
        "evidence_completeness": "1.000000",
        "impact_weighted_verified_yield": "6.000000",
        "tudy": "1.500000",
    }


def test_metrics_use_decimal_and_fixed_six_place_output() -> None:
    manifest = _manifest()
    results = _results(manifest, budget=Decimal("18"))

    metrics = _full_variant(aggregate_trials(manifest, results))["metrics"]

    assert metrics["tudy"] == "0.333333"
    assert all(
        isinstance(value, str) and len(value.rsplit(".", maxsplit=1)[-1]) == 6
        for value in metrics.values()
    )


def test_unsealed_results_are_reportable_but_never_certifying() -> None:
    manifest = _manifest(sealed=False)
    report = aggregate_trials(manifest, _results(manifest))

    assert report["status"] == "NON_CERTIFYING"
    assert report["m0_demonstrated"] is False
    assert report["gates"]["benchmark_sealed"] is False
    with pytest.raises(PolicyError) as raised:
        certify_m0(report)
    assert raised.value.code == "POLICY_DENIED"


@pytest.mark.parametrize("custody_field", ["independent", "sealed_before_explorer"])
def test_invalid_external_custody_is_not_self_certifiable(custody_field: str) -> None:
    manifest = _manifest()
    manifest["custody"][custody_field] = False
    report = aggregate_trials(manifest, _results(manifest))

    assert report["status"] == "NON_CERTIFYING"
    assert report["m0_demonstrated"] is False
    with pytest.raises(PolicyError):
        certify_m0(report)


def test_control_verified_claim_fails_zero_false_positive_gate() -> None:
    manifest = _manifest()
    results = _results(manifest)
    full = next(item for item in results if item["variant"] == FULL_SYSTEM_VARIANT)
    control = next(item for item in full["findings"] if item["case_id"] == "C-1")
    for flag in control:
        if flag != "case_id":
            control[flag] = True

    report = aggregate_trials(manifest, results)

    assert report["status"] == "NON_CERTIFYING"
    assert report["gates"]["control_threshold_met"] is False
    assert report["gates"]["no_false_verified_claims"] is False
    assert _full_variant(report)["metrics"]["control_false_positive_rate"] == "0.500000"


def test_verified_control_cannot_hide_behind_false_claimed_flag() -> None:
    manifest = _manifest()
    results = _results(manifest)
    full = next(item for item in results if item["variant"] == FULL_SYSTEM_VARIANT)
    control = next(item for item in full["findings"] if item["case_id"] == "C-1")
    control["verified"] = True
    control["claimed_verified"] = False

    report = aggregate_trials(manifest, results)

    assert report["gates"]["control_threshold_met"] is False
    assert report["gates"]["no_false_verified_claims"] is False
    assert "C-1" in _full_variant(report)["false_verified_control_ids"]


def test_case_mix_and_all_five_ablations_are_hard_gates() -> None:
    short_manifest = _manifest(positive_count=4)
    short = aggregate_trials(short_manifest, _results(short_manifest))
    assert short["gates"]["case_mix_exact"] is False
    assert short["m0_demonstrated"] is False

    manifest = _manifest()
    partial = aggregate_trials(manifest, _results(manifest)[:-1])
    assert partial["gates"]["ablation_coverage_complete"] is False
    assert partial["gates"]["full_system_case_coverage"] is False
    assert partial["m0_demonstrated"] is False


def test_output_is_canonical_across_input_ordering() -> None:
    manifest = _manifest()
    first_results = _results(manifest)
    first = aggregate_trials(manifest, first_results)

    reordered_manifest = deepcopy(manifest)
    reordered_manifest["cases"].reverse()
    reordered_results = deepcopy(first_results)
    reordered_results.reverse()
    for result in reordered_results:
        result["findings"].reverse()
        result["manifest_hash"] = manifest_digest(reordered_manifest)
    second = aggregate_trials(reordered_manifest, reordered_results)

    assert second == first
    assert second["report_hash"] == first["report_hash"]


def test_manifest_binding_and_report_recomputation_fail_closed() -> None:
    manifest = _manifest()
    results = _results(manifest)
    results[0]["manifest_hash"] = "b" * 64
    with pytest.raises(IntegrityError):
        aggregate_trials(manifest, results)

    report = aggregate_trials(manifest, _results(manifest))
    report["suite_id"] = "M0-SUITE-TAMPERED"
    report["report_hash"] = hash_json(
        {key: value for key, value in report.items() if key != "report_hash"}
    )
    with pytest.raises(IntegrityError):
        certify_m0(report)
