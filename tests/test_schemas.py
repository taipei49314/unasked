from __future__ import annotations

from copy import deepcopy

import pytest

from unasked.schemas import (
    SCHEMA_DRAFT,
    SchemaNotFoundError,
    SchemaValidationError,
    is_valid,
    list_schemas,
    show_schema,
    validate_or_raise,
    validate_schema,
)
from unasked.trials import ABLATION_VARIANTS, aggregate_trials, manifest_digest
from unasked.util import hash_json

HASH = "a" * 64
OTHER_HASH = "b" * 64
COMMIT = "c" * 40
NOW = "2026-08-09T09:00:00Z"


def actor(role: str, *capabilities: str) -> dict:
    return {
        "actor_id": role.lower().replace("_", "-"),
        "role": role,
        "capabilities": list(capabilities),
    }


def artifact(artifact_id: str) -> dict:
    return {"artifact_id": artifact_id, "sha256": HASH}


def valid_examples() -> dict[str, dict]:
    explorer = actor("EXPLORER", "OBSERVE", "PROPOSE_CANDIDATE")
    planner = actor("EXPERIMENT_PLANNER", "REQUEST_EXPERIMENT")
    executor = actor("SANDBOX_EXECUTOR", "EXECUTE_SANDBOX", "SUBMIT_EVIDENCE")
    falsifier = actor("FALSIFIER", "CHALLENGE")
    reproducer = actor("INDEPENDENT_REPRODUCER", "REPLAY")
    authority = actor("DISCOVERY_AUTHORITY_KERNEL", "AUTHORIZE_VERDICT")

    source = {
        "source_type": "DOCUMENTATION",
        "path": "README.md",
        "sha256": HASH,
        "snapshot_hash": OTHER_HASH,
    }
    checks = {
        "snapshot_bound": True,
        "evidence_complete": True,
        "clean_replay_passed": True,
        "counterevidence_completed": True,
        "known_issue_scan_completed": True,
        "protocol_frozen": True,
        "hashes_consistent": True,
        "authority_separated": True,
        "materiality_approved": True,
    }
    budget_policy = {
        "schema_version": "0.1.0",
        "max_turns": 12,
        "max_provider_calls": 12,
        "max_tool_calls": 8,
        "max_candidates": 2,
        "max_experiments": 2,
        "max_experiment_commands": 4,
        "max_wall_seconds": 300,
        "max_request_bytes": 262_144,
        "max_response_bytes": 65_536,
        "max_total_request_bytes": 1_048_576,
        "max_file_bytes": 65_536,
        "max_search_matches": 64,
        "max_inventory_entries": 500,
        "max_observations": 500,
    }
    trial_manifest = {
        "suite_id": "M0-SUITE-1",
        "cases": [
            *[
                {"case_id": f"P-{index}", "kind": "POSITIVE", "impact_weight": index}
                for index in range(1, 6)
            ],
            {"case_id": "C-1", "kind": "CONTROL", "impact_weight": 0},
            {"case_id": "C-2", "kind": "CONTROL", "impact_weight": 0},
        ],
        "custody": {
            "status": "UNSEALED",
            "independent": False,
            "sealed_before_explorer": False,
        },
    }
    trial_results = [
        {
            "variant": variant,
            "manifest_hash": manifest_digest(trial_manifest),
            "protocol_hash": HASH,
            "normalized_budget": 10,
            "findings": [
                {
                    "case_id": case["case_id"],
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
                for case in trial_manifest["cases"]
            ],
        }
        for variant in ABLATION_VARIANTS
    ]
    baseline_signal = {
        "schema_version": "0.1.0",
        "signal_id": "SIG-000001",
        "record_type": "DETERMINISTIC_SIGNAL",
        "run_id": "R-000001",
        "snapshot_hash": HASH,
        "snapshot_commit": COMMIT,
        "protocol_hash": HASH,
        "detector": {
            "name": "deterministic-control-signal-baseline",
            "version": "0.1.0",
        },
        "rule_id": "control-signal/skip",
        "category": "skip",
        "source_observation_id": "O-000001",
        "source": {
            "path": "tests/test_feature.py",
            "sha256": OTHER_HASH,
            "line_start": 4,
            "line_end": 4,
            "git_object": COMMIT,
        },
        "evidence": {
            "matched_text": "pytest.mark.skip",
            "line_text": "@pytest.mark.skip(reason='fixture')",
        },
        "claim_scope": "NON_DISCOVERY_SIGNAL_ONLY",
        "lifecycle_effect": "NONE",
    }
    baseline_signal["record_hash"] = hash_json(baseline_signal)
    baseline_result = {
        "schema_version": "0.1.0",
        "record_type": "DETERMINISTIC_BASELINE_RESULT",
        "baseline_run_id": "BASE-000001",
        "run_id": "R-000001",
        "snapshot_hash": HASH,
        "snapshot_commit": COMMIT,
        "protocol_hash": HASH,
        "protocol_version": "0.1.0-p0",
        "detector": {
            "name": "deterministic-control-signal-baseline",
            "version": "0.1.0",
            "rules": ["continue_on_error", "skip", "suppression"],
            "benchmark_specific_rules": False,
        },
        "observation_manifest_hash": OTHER_HASH,
        "claim_scope": "NON_DISCOVERY_SIGNAL_ONLY",
        "lifecycle_effect": "NONE",
        "signal_count": 1,
        "signals": [baseline_signal],
        "normalized_budget": {
            "policy_id": "UNASKED-NORMALIZED-STATIC-SCAN-v1",
            "unit": "normalized_investigation_unit",
            "formula": ("snapshot_entries + ceil(snapshot_bytes / 1024) + observations_classified"),
            "usage": {
                "snapshot_passes": 1,
                "snapshot_entries": 0,
                "snapshot_bytes": 0,
                "snapshot_kib_units": 0,
                "observations_classified": 0,
                "model_calls": 0,
                "network_requests": 0,
                "experiment_commands": 0,
            },
            "consumed_units": 0,
            "workload_bound_units": 0,
            "within_workload_bound": True,
        },
        "integration": {
            "canonical_encoding": "unasked.canonical_json",
            "media_type": "application/vnd.unasked.deterministic-baseline+json",
            "ledger_event_type": "DETERMINISTIC_BASELINE_COMPLETED",
        },
    }
    explorer_action = {
        "action": "PROPOSE",
        "expectation": {
            "expectation_type": "explicit",
            "statement": "The documented command should print expected.",
            "reasoning_chain": ["The README states an unconditional behavior claim."],
            "source_observation_ids": ["O-000001"],
            "strength": "strong",
        },
        "candidate": {
            "observation_ids": ["O-000001"],
            "discrepancy": "The executable prints a different value.",
            "materiality_question": "Would this change release confidence?",
            "main_hypothesis": "Runtime output contradicts the README claim.",
            "benign_alternatives": ["The README may describe another invocation."],
            "falsification_conditions": ["The command prints expected."],
            "minimal_experiment": "Run a fixed minimal command.",
            "supporting_outcomes": ["stdout differs"],
            "falsifying_outcomes": ["stdout matches"],
            "inconclusive_outcomes": ["the interpreter cannot run"],
            "estimated_seconds": 5,
            "risk_level": "low",
            "risks": ["sandbox-only process execution"],
        },
        "plan": {
            "commands": [
                {
                    "command_id": "CMD-PROBE",
                    "argv": ["python", "-c", "print('actual')"],
                    "working_directory": ".",
                    "purpose": "Capture exact runtime output.",
                    "expected_observation": "stdout is actual or expected.",
                }
            ],
            "support_criteria": ["stdout differs"],
            "falsify_criteria": ["stdout matches"],
            "inconclusive_criteria": ["the command cannot run"],
            "outcome_assertions": [
                {
                    "assertion_id": "A-SUPPORT",
                    "command_id": "CMD-PROBE",
                    "field": "STDOUT_SHA256",
                    "operator": "EQUALS",
                    "expected": HASH,
                    "classification": "SUPPORTS",
                },
                {
                    "assertion_id": "A-FALSIFY",
                    "command_id": "CMD-PROBE",
                    "field": "EXIT_CODE",
                    "operator": "EQUALS",
                    "expected": 1,
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
    investigation_result = {
        "schema_version": "0.1.0",
        "run_id": "R-000001",
        "started_at": NOW,
        "completed_at": NOW,
        "status": "COMPLETED",
        "stop_reason": "PROVIDER_STOPPED",
        "mode": "full_evidence_gated",
        "provider": {
            "provider": "scripted",
            "model": "fixture-model",
            "adapter": "offline_recorded_json",
            "response_count": 1,
            "transcript_hash": HASH,
            "network_isolation_enforced": True,
            "certifying": False,
        },
        "budget": {
            "limits": budget_policy,
            "consumed": {
                "turns": 1,
                "provider_calls": 1,
                "tool_calls": 0,
                "candidates": 0,
                "experiments": 0,
                "request_bytes": 1024,
                "response_bytes": 48,
                "elapsed_seconds": 0.125,
            },
        },
        "result": {
            "candidate_count": 0,
            "candidate_states": {},
            "verified_count": 0,
            "next_required_stages": [
                "independent_falsifier",
                "external_isolated_replay",
                "independent_reviews",
                "authority_verdict",
            ],
        },
        "provenance": {
            "turn_count": 1,
            "turn_artifact_hashes": [HASH],
            "budget_policy_hash": hash_json(budget_policy),
            "target_snapshot_hash": OTHER_HASH,
            "protocol_hash": HASH,
            "human_steering_count": 0,
        },
        "certification": {
            "status": "NON_CERTIFYING",
            "reason_codes": [
                "BENCHMARK_NOT_INDEPENDENTLY_SEALED",
                "DEVELOPMENT_PROVIDER_NON_CERTIFYING",
            ],
            "m0_demonstrated": False,
            "engineering_demo_completed": True,
            "allowed_claim": (
                "A research harness for blind, evidence-gated repository investigation."
            ),
        },
    }

    return {
        "baseline-result": baseline_result,
        "budget-policy": budget_policy,
        "explorer-action": explorer_action,
        "investigation-result": investigation_result,
        "trial-manifest": trial_manifest,
        "trial-report": aggregate_trials(trial_manifest, trial_results),
        "run": {
            "schema_version": "0.1.0",
            "run_id": "R-000001",
            "created_at": NOW,
            "status": "CREATED",
            "target": {
                "repository_commit": COMMIT,
                "snapshot_hash": HASH,
            },
            "protocol": {"version": "0.1.0-p0", "sha256": HASH, "frozen_at": NOW},
            "model": {"provider": "example", "name": "model"},
            "tools": [{"name": "git", "version": "2.50.0"}],
            "context_manifest_hash": HASH,
            "knowledge_boundary_hash": OTHER_HASH,
        },
        "observation": {
            "schema_version": "0.1.0",
            "observation_id": "O-000001",
            "run_id": "R-000001",
            "observed_at": NOW,
            "kind": "CLAIM",
            "statement": "The README declares support for the feature.",
            "source": source,
            "acquisition": {
                "method": "READ",
                "actor_id": "explorer",
                "tool": {"name": "reader", "version": "1"},
            },
            "integrity": {"status": "COMPLETE", "content_hash": HASH},
            "snapshot_hash": OTHER_HASH,
        },
        "expectation": {
            "schema_version": "0.1.0",
            "expectation_id": "E-000001",
            "run_id": "R-000001",
            "created_at": NOW,
            "expectation_type": "EXPLICIT",
            "statement": "The documented feature should be reachable.",
            "sources": [source],
            "reasoning_chain": ["The support statement is unconditional."],
            "strength": "STRONG",
            "snapshot_hash": OTHER_HASH,
        },
        "candidate": {
            "schema_version": "0.1.0",
            "candidate_id": "C-000001",
            "run_id": "R-000001",
            "created_at": NOW,
            "state": "CANDIDATE",
            "expectation_ids": ["E-000001"],
            "observation_ids": ["O-000001"],
            "discrepancy": "The declared feature has no reachable entry point.",
            "materiality_question": "Would this change the support decision?",
            "origin": "MODEL_EXPLORER",
            "provenance": {
                "prompt_hash": HASH,
                "context_manifest_hash": OTHER_HASH,
                "human_direction_provided": False,
            },
            "proposed_by": explorer,
            "snapshot_hash": OTHER_HASH,
        },
        "hypothesis": {
            "schema_version": "0.1.0",
            "hypothesis_id": "H-000001",
            "candidate_id": "C-000001",
            "run_id": "R-000001",
            "created_at": NOW,
            "state": "TESTABLE",
            "main_hypothesis": "The documented entry point is unreachable.",
            "benign_alternatives": ["The entry point is generated during packaging."],
            "falsification_conditions": ["A clean build exposes the entry point."],
            "minimal_experiment": "Build and query the public entry points.",
            "expected_observations": {
                "supporting": ["The entry point remains absent."],
                "falsifying": ["The entry point is present."],
                "inconclusive": ["The build cannot run."],
            },
            "cost_and_risk": {
                "estimated_seconds": 60,
                "risk_level": "LOW",
                "risks": [],
            },
            "required_capabilities": ["REQUEST_EXPERIMENT", "EXECUTE_SANDBOX"],
            "proposed_by": explorer,
            "snapshot_hash": OTHER_HASH,
        },
        "knowledge-scan": {
            "schema_version": "0.1.0",
            "scan_id": "KS-000001",
            "run_id": "R-000001",
            "completed_at": NOW,
            "status": "COMPLETE",
            "knowledge_boundary_hash": HASH,
            "target_snapshot_hash": OTHER_HASH,
            "categories": ["repository documentation"],
            "source_manifest": [source],
            "raw_observations_ref": artifact("AR-RAW"),
            "evidence_hashes": [HASH],
            "scope_attestation": {
                "repository_snapshot_fully_scanned": True,
                "supplied_external_sources_fully_scanned": True,
                "omitted_sources": [],
            },
            "scanner": explorer,
        },
        "experiment-plan": {
            "schema_version": "0.1.0",
            "plan_id": "P-000001",
            "hypothesis_id": "H-000001",
            "run_id": "R-000001",
            "created_at": NOW,
            "protocol_hash": HASH,
            "snapshot_hash": OTHER_HASH,
            "isolation": {
                "worktree": "ISOLATED",
                "network": "DISABLED",
                "secret_free": True,
                "mutation_scope": "SANDBOX_ONLY",
                "limits": {
                    "cpu_seconds": 60,
                    "wall_seconds": 120,
                    "disk_bytes": 1000000,
                    "processes": 4,
                },
            },
            "commands": [
                {
                    "command_id": "CMD-1",
                    "argv": ["python", "-m", "pytest"],
                    "purpose": "Exercise the public entry point.",
                    "expected_observation": "The entry point is absent or present.",
                }
            ],
            "outcome_criteria": {
                "support": ["The entry point remains absent."],
                "falsify": ["The entry point is present."],
                "inconclusive": ["The environment cannot execute the build."],
            },
            "outcome_assertions": [
                {
                    "assertion_id": "A-SUPPORT",
                    "command_id": "CMD-1",
                    "field": "STDOUT_SHA256",
                    "operator": "EQUALS",
                    "expected": HASH,
                    "classification": "SUPPORTS",
                },
                {
                    "assertion_id": "A-FALSIFY",
                    "command_id": "CMD-1",
                    "field": "EXIT_CODE",
                    "operator": "EQUALS",
                    "expected": 1,
                    "classification": "FALSIFIES",
                },
            ],
            "required_capabilities": ["EXECUTE_SANDBOX"],
            "planner": planner,
        },
        "evidence-reference": {
            "schema_version": "0.1.0",
            "evidence_id": "EV-000001",
            "run_id": "R-000001",
            "kind": "STDOUT",
            "sha256": HASH,
            "uri": "cas/sha256/aa/output.txt",
            "size_bytes": 42,
            "media_type": "text/plain",
            "created_at": NOW,
            "producer": executor,
            "provenance": {
                "immutable": True,
                "target_snapshot_hash": OTHER_HASH,
                "command_id": "CMD-1",
            },
        },
        "experiment-result": {
            "schema_version": "0.1.0",
            "result_id": "XR-000001",
            "plan_id": "P-000001",
            "run_id": "R-000001",
            "started_at": NOW,
            "completed_at": NOW,
            "status": "SUCCEEDED",
            "observed_outcome": "SUPPORTS",
            "environment_hash": HASH,
            "executions": [
                {
                    "command_id": "CMD-1",
                    "started_at": NOW,
                    "completed_at": NOW,
                    "exit_code": 0,
                    "stdout_ref": artifact("stdout-1"),
                    "stderr_ref": artifact("stderr-1"),
                    "artifact_refs": [],
                }
            ],
            "evidence_refs": [artifact("EV-000001")],
            "executor": executor,
        },
        "replay-result": {
            "schema_version": "0.1.0",
            "replay_id": "RP-000001",
            "run_id": "R-REPLAY-1",
            "source_run_id": "R-000001",
            "hypothesis_id": "H-000001",
            "started_at": NOW,
            "completed_at": NOW,
            "status": "PASS",
            "clean_environment": True,
            "environment_hash": HASH,
            "core_result_match": True,
            "residual_state_detected": False,
            "command_result_refs": [artifact("replay-command-1")],
            "evidence_hashes": [HASH],
            "reproducer": reproducer,
            "independence_attestation": {
                "no_explorer_state": True,
                "no_unrecorded_files": True,
                "input_manifest_hash": OTHER_HASH,
            },
        },
        "review": {
            "schema_version": "0.1.0",
            "review_id": "RV-000001",
            "candidate_id": "C-000001",
            "run_id": "R-000001",
            "review_type": "COUNTEREVIDENCE",
            "reviewed_at": NOW,
            "reviewer": falsifier,
            "conclusion": "PASS",
            "findings": ["The candidate survived the declared alternative."],
            "evidence_hashes": [HASH],
            "tested_alternatives": ["Packaging generates the entry point."],
            "negative_control": "A fixture with a generated entry point succeeds.",
            "semantic_variant": "Renaming unrelated files does not change the result.",
            "completeness_check": "The package manifest was inspected.",
            "challenge_attempts": [
                {
                    "attempt_id": f"CH-{index}",
                    "attempt_type": attempt_type,
                    "description": "A predeclared challenge was executed.",
                    "predeclared_input_hash": OTHER_HASH,
                    "result_ref": artifact(f"challenge-{index}"),
                    "observed_outcome": "SURVIVED",
                }
                for index, attempt_type in enumerate(
                    (
                        "BENIGN_ALTERNATIVE",
                        "NEGATIVE_CONTROL",
                        "SEMANTIC_VARIANT",
                        "COMPLETENESS_CHECK",
                    ),
                    start=1,
                )
            ],
        },
        "verdict": {
            "schema_version": "0.1.0",
            "verdict_id": "V-000001",
            "candidate_id": "C-000001",
            "run_id": "R-000001",
            "issued_at": NOW,
            "status": "VERIFIED",
            "authority_actor": authority,
            "policy_hash": HASH,
            "reasons": ["Every predeclared authorization check passed."],
            "checks": checks,
            "proposer_actor_id": "explorer",
            "executor_actor_id": "sandbox-executor",
            "separation_attestation": True,
            "evidence_bundle_hash": HASH,
            "replay_result_hash": HASH,
            "counterevidence_review_hash": HASH,
            "novelty_review_hash": HASH,
            "materiality_review_hash": HASH,
        },
        "discovery-certificate": {
            "schema_version": "0.1.0",
            "certificate_id": "D-000001",
            "run_id": "R-000001",
            "candidate_id": "C-000001",
            "hypothesis_id": "H-000001",
            "issued_at": NOW,
            "status": "VERIFIED",
            "belief_update": {
                "before": "The documented entry point is supported.",
                "after": "The entry point is absent at the bound snapshot.",
            },
            "expectation_refs": [artifact("E-000001")],
            "observation_refs": [artifact("O-000001")],
            "main_hypothesis": "The documented entry point is unreachable.",
            "alternative_explanations": ["Packaging generates the entry point."],
            "falsification_conditions": ["A clean build exposes the entry point."],
            "experiment_plan_ref": artifact("P-000001"),
            "experiment_result_ref": artifact("XR-000001"),
            "counterevidence_review_ref": artifact("RV-COUNTER-1"),
            "replay_result_ref": artifact("RP-000001"),
            "novelty_review_ref": artifact("RV-NOVELTY-1"),
            "materiality_review_ref": artifact("RV-MATERIALITY-1"),
            "knowledge_boundary_hash": HASH,
            "decision_impact": "The support matrix must change.",
            "limitations": ["Only the bound snapshot was tested."],
            "unconfirmed": [],
            "verdict_ref": artifact("V-000001"),
            "authorization": {
                "authority_actor": authority,
                "policy_hash": HASH,
                "authorized_at": NOW,
            },
            "evidence_hashes": [HASH],
            "evidence_bundle_hash": HASH,
            "snapshot_binding": {
                "repository_commit": COMMIT,
                "target_snapshot_hash": HASH,
                "protocol_hash": HASH,
                "policy_hash": HASH,
                "knowledge_boundary_hash": HASH,
                "context_manifest_hash": HASH,
                "tool_versions": [{"name": "git", "version": "2.50.0"}],
            },
        },
        "event": {
            "schema_version": "0.1.0",
            "event_id": "EVT-000001",
            "run_id": "R-000001",
            "sequence": 0,
            "occurred_at": NOW,
            "event_type": "RUN_CREATED",
            "actor": actor("SYSTEM"),
            "payload": {"status": "CREATED"},
            "artifact_refs": [],
            "previous_event_hash": None,
            "event_hash": HASH,
        },
    }


def test_public_schema_list_is_stable_and_complete() -> None:
    expected = (
        "baseline-result",
        "budget-policy",
        "candidate",
        "discovery-certificate",
        "event",
        "evidence-reference",
        "expectation",
        "experiment-plan",
        "experiment-result",
        "explorer-action",
        "hypothesis",
        "investigation-result",
        "knowledge-scan",
        "observation",
        "replay-result",
        "review",
        "run",
        "trial-manifest",
        "trial-report",
        "verdict",
    )
    assert list_schemas() == expected
    assert set(valid_examples()) == set(expected)


@pytest.mark.parametrize("schema_name", list_schemas())
def test_valid_examples_pass(schema_name: str) -> None:
    example = valid_examples()[schema_name]
    assert validate_schema(schema_name, example) == ()
    assert is_valid(schema_name, example)
    validate_or_raise(schema_name, example)


def test_show_schema_is_draft_2020_12_and_returns_a_copy() -> None:
    first = show_schema("experiment_plan.json")
    assert first["$schema"] == SCHEMA_DRAFT
    first["title"] = "mutated"
    assert show_schema("experiment-plan")["title"] != "mutated"


def test_missing_required_field_has_stable_pointer_and_code() -> None:
    instance = valid_examples()["run"]
    del instance["run_id"]

    first = validate_schema("run", instance)
    second = validate_schema("run", instance)

    assert first == second
    assert [issue.to_dict() for issue in first] == [
        {
            "path": "/run_id",
            "code": "required",
            "message": "Required property is missing: run_id.",
            "schema_path": "/required",
        }
    ]
    with pytest.raises(SchemaValidationError) as raised:
        validate_or_raise("run", instance)
    assert raised.value.code == "SCHEMA_VALIDATION_FAILED"
    assert raised.value.errors == first


@pytest.mark.parametrize(
    ("schema_name", "field", "illegal"),
    [
        ("run", "status", "DISCOVERED"),
        ("candidate", "state", "VERIFIED"),
        ("verdict", "status", "SUPPORTED"),
        ("discovery-certificate", "status", "SUPPORTED"),
    ],
)
def test_illegal_states_are_rejected(schema_name: str, field: str, illegal: str) -> None:
    instance = valid_examples()[schema_name]
    instance[field] = illegal
    issues = validate_schema(schema_name, instance)
    assert any(issue.path == f"/{field}" and issue.code in {"const", "enum"} for issue in issues)


def test_verified_verdict_cannot_bypass_required_gates() -> None:
    instance = deepcopy(valid_examples()["verdict"])
    instance["checks"]["clean_replay_passed"] = False
    del instance["counterevidence_review_hash"]

    issues = validate_schema("verdict", instance)

    assert any(
        issue.path == "/checks/clean_replay_passed" and issue.code == "const" for issue in issues
    )
    assert any(
        issue.path == "/counterevidence_review_hash" and issue.code == "required"
        for issue in issues
    )


def test_investigation_result_accepts_persisted_and_enriched_return_shapes() -> None:
    persisted = deepcopy(valid_examples()["investigation-result"])
    assert validate_schema("investigation-result", persisted) == ()

    returned = deepcopy(persisted)
    returned.update(
        {
            "ledger": {
                "valid": True,
                "entries": 3,
                "last_hash": HASH,
                "error": None,
                "line": None,
                "sequence": None,
                "details": {},
            },
            "tool_version": "0.1.0",
            "claim": "A research harness for blind, evidence-gated repository investigation.",
            "provider_failed": False,
        }
    )
    assert validate_schema("investigation-result", returned) == ()


def test_m0_schema_fail_closed_constraints_reject_bypasses() -> None:
    budget = deepcopy(valid_examples()["budget-policy"])
    budget["max_turns"] = 0
    assert any(issue.path == "/max_turns" for issue in validate_schema("budget-policy", budget))

    action = deepcopy(valid_examples()["explorer-action"])
    action["requested_state"] = "VERIFIED"
    assert validate_schema("explorer-action", action)

    report = deepcopy(valid_examples()["trial-report"])
    report["status"] = "M0_DEMONSTRATED"
    report["m0_demonstrated"] = True
    assert validate_schema("trial-report", report)


def test_sealed_aggregate_stays_non_certifying_and_passes_trial_report_schema() -> None:
    manifest = deepcopy(valid_examples()["trial-manifest"])
    manifest["custody"] = {
        "status": "SEALED",
        "independent": True,
        "sealed_before_explorer": True,
    }
    digest = manifest_digest(manifest)
    results = []
    for variant in ABLATION_VARIANTS:
        findings = []
        for case in manifest["cases"]:
            trusted = (
                variant == "full-evidence-gated-system"
                and case["kind"] == "POSITIVE"
                and case["case_id"] in {"P-1", "P-2", "P-3"}
            )
            findings.append(
                {
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
            )
        results.append(
            {
                "variant": variant,
                "manifest_hash": digest,
                "protocol_hash": HASH,
                "normalized_budget": 10,
                "findings": findings,
            }
        )

    report = aggregate_trials(manifest, results)
    assert report["m0_demonstrated"] is False
    assert report["gates"]["external_evidence_verified"] is False
    assert validate_schema("trial-report", report) == ()


def test_unknown_schema_has_stable_machine_code() -> None:
    with pytest.raises(SchemaNotFoundError) as raised:
        show_schema("not-a-schema")
    assert raised.value.code == "SCHEMA_NOT_FOUND"
    assert raised.value.available == list_schemas()
