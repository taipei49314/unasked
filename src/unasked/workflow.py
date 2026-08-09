from __future__ import annotations

import json
import platform
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from unasked import __version__
from unasked.artifacts import ArtifactMetadata, ArtifactStore
from unasked.errors import PolicyError, UnaskedError, UsageError
from unasked.observer import observe_repository
from unasked.outcomes import classify_outcome
from unasked.policy import Actor, Capability, State, require_capability
from unasked.project import SCHEMA_VERSION, Project
from unasked.repository import temporary_worktree
from unasked.sandbox import ISOLATION_NOTICE, RestrictedExecutor
from unasked.schemas import validate_or_raise
from unasked.util import canonical_json, hash_json, read_json, sha256_file, utc_now


def _source_type(raw_kind: str, path: str) -> str:
    if raw_kind == "documentation_claim_source":
        return "DOCUMENTATION"
    if raw_kind == "test_path":
        return "TEST"
    if "/.github/workflows/" in f"/{path}" or raw_kind.startswith("ci_"):
        return "CI_METADATA"
    return "SOURCE"


def _observation_kind(raw_kind: str, fact: dict[str, Any]) -> str:
    if raw_kind == "documentation_claim_source":
        return "CLAIM"
    if raw_kind == "test_path":
        return "TEST_PATH"
    if raw_kind.startswith("ci_"):
        return "WORKFLOW"
    if raw_kind == "control_signal" and fact.get("category") in {
        "skip",
        "suppression",
        "continue_on_error",
    }:
        return "SUPPRESSION"
    return "STRUCTURE"


def _deduplicate_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for reference in refs:
        unique[(reference["artifact_id"], reference["sha256"])] = reference
    return [unique[key] for key in sorted(unique)]


@dataclass
class InvestigationService:
    project: Project

    @property
    def store(self) -> ArtifactStore:
        return ArtifactStore(self.project.artifacts_root)

    def observe(self, run_id: str, *, actor: Actor) -> dict[str, Any]:
        require_capability(actor, Capability.OBSERVE)
        target = self.project.get_target(run_id)
        scan_path = self.project.paths(run_id).root / "knowledge-scan.json"
        if scan_path.exists():
            raise PolicyError("The frozen repository knowledge scan is already complete.")
        raw = observe_repository(target["repository_path"], target)
        raw_meta = self.store.put_bytes(
            canonical_json(raw),
            media_type="application/json",
            original_name=f"{run_id}-raw-observations.json",
        )
        normalized: list[dict[str, Any]] = []
        for item in raw:
            source = item["source"]
            record = {
                "schema_version": SCHEMA_VERSION,
                "observation_id": item["observation_id"],
                "run_id": run_id,
                "observed_at": item["captured_at"],
                "kind": _observation_kind(item["kind"], item["fact"]),
                "statement": json.dumps(
                    item["fact"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                "source": {
                    "source_type": _source_type(item["kind"], source["path"]),
                    "path": source["path"],
                    "locator": f"L{source['line_start']}-L{source['line_end']}",
                    "sha256": source["sha256"],
                    "snapshot_hash": target["snapshot_hash"],
                },
                "acquisition": {
                    "method": "PARSE",
                    "actor_id": actor.actor_id,
                    "tool": {"name": "unasked-observer", "version": __version__},
                },
                "integrity": {
                    "status": "COMPLETE",
                    "content_hash": source["sha256"],
                    "notes": "Fact extracted without discovery interpretation.",
                },
                "snapshot_hash": target["snapshot_hash"],
            }
            enriched = self.project.append_record(
                run_id,
                collection="observations",
                schema_name="observation",
                record=record,
                actor=actor,
                event_type="OBSERVATION_RECORDED",
            )
            normalized.append(enriched)
        self.project.ledger(run_id).append(
            "OBSERVATION_BATCH_CAPTURED",
            {"count": len(normalized), "raw_sha256": raw_meta.sha256},
            actor=actor.to_dict(),
            artifact_refs=[raw_meta.to_reference()],
        )
        run = self.project.get_run(run_id)
        boundary = read_json(self.project.paths(run_id).knowledge_boundary)
        sources_by_hash = {hash_json(record["source"]): record["source"] for record in normalized}
        knowledge_scan = {
            "schema_version": SCHEMA_VERSION,
            "scan_id": f"KS-{run_id[4:]}",
            "run_id": run_id,
            "completed_at": utc_now(),
            "status": "COMPLETE",
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "target_snapshot_hash": target["snapshot_hash"],
            "categories": boundary["categories"],
            "source_manifest": [sources_by_hash[digest] for digest in sorted(sources_by_hash)],
            "raw_observations_ref": raw_meta.to_reference(),
            "evidence_hashes": [raw_meta.sha256],
            "scope_attestation": {
                "repository_snapshot_fully_scanned": True,
                "supplied_external_sources_fully_scanned": True,
                "omitted_sources": [],
            },
            "scanner": actor.to_dict(),
        }
        self.project.write_run_artifact(
            run_id,
            "knowledge-scan.json",
            knowledge_scan,
            actor=actor,
            event_type="KNOWLEDGE_SCAN_COMPLETED",
            schema_name="knowledge-scan",
        )
        return {
            "run_id": run_id,
            "observations": len(normalized),
            "raw_artifact": raw_meta.to_reference(),
            "knowledge_scan": knowledge_scan,
        }

    def record_custody_attestation(
        self,
        run_id: str,
        *,
        actor: Actor,
        sealed_manifest_hash: str,
        access_log_hash: str,
        sealed_at: str,
        external_store_reference: str,
    ) -> dict[str, Any]:
        if actor.role.casefold() not in {"principal_investigator", "human_judge"}:
            raise PolicyError("Only an external custodian role may attest benchmark custody.")
        for field, value in {
            "sealed_manifest_hash": sealed_manifest_hash,
            "access_log_hash": access_log_hash,
        }.items():
            try:
                valid = (
                    len(value) == 64 and value == value.lower() and len(bytes.fromhex(value)) == 32
                )
            except ValueError:
                valid = False
            if not valid:
                raise UsageError(f"{field} must be a lowercase SHA-256 digest.")
        run = self.project.get_run(run_id)
        try:
            sealed_time = datetime.fromisoformat(sealed_at.replace("Z", "+00:00"))
            run_time = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise UsageError("sealed_at must be an ISO-8601 timestamp.") from exc
        if sealed_time > run_time:
            raise PolicyError("Benchmark custody must be sealed before the investigation run.")
        attestation = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "recorded_at": utc_now(),
            "sealed_at": sealed_at,
            "sealed_manifest_hash": sealed_manifest_hash,
            "access_log_hash": access_log_hash,
            "external_store_reference": external_store_reference,
            "custodian": actor.to_dict(),
            "sealed_before_explorer": True,
            "explorer_ground_truth_access": False,
            "directional_steering": False,
            "attestation_method": "external operator declaration",
        }
        self.project.write_run_artifact(
            run_id,
            "custody-attestation.json",
            attestation,
            actor=actor,
            event_type="BENCHMARK_CUSTODY_ATTESTED",
        )
        return attestation

    def add_expectation(
        self,
        run_id: str,
        *,
        actor: Actor,
        expectation_type: str,
        statement: str,
        reasoning_chain: list[str],
        source_observation_ids: list[str],
        strength: str,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.PROPOSE_CANDIDATE)
        target = self.project.get_target(run_id)
        observations = {
            record["observation_id"]: record
            for record in self.project.records(run_id, "observations")
        }
        missing = sorted(set(source_observation_ids) - observations.keys())
        if missing:
            raise UsageError(
                "Expectation references unknown observations.", details={"missing": missing}
            )
        sources = [
            {key: value for key, value in observations[item]["source"].items()}
            for item in source_observation_ids
        ]
        expectation_id = self.project.next_id(run_id, "E", collection="expectations")
        record = {
            "schema_version": SCHEMA_VERSION,
            "expectation_id": expectation_id,
            "run_id": run_id,
            "created_at": utc_now(),
            "expectation_type": expectation_type.upper(),
            "statement": statement,
            "sources": sources,
            "reasoning_chain": reasoning_chain,
            "strength": strength.upper(),
            "snapshot_hash": target["snapshot_hash"],
        }
        return self.project.append_record(
            run_id,
            collection="expectations",
            schema_name="expectation",
            record=record,
            actor=actor,
            event_type="EXPECTATION_RECORDED",
        )

    def propose_candidate(
        self,
        run_id: str,
        *,
        actor: Actor,
        expectation_ids: list[str],
        observation_ids: list[str],
        discrepancy: str,
        materiality_question: str,
        origin: str,
        main_hypothesis: str,
        benign_alternatives: list[str],
        falsification_conditions: list[str],
        minimal_experiment: str,
        supporting_outcomes: list[str],
        falsifying_outcomes: list[str],
        inconclusive_outcomes: list[str],
        estimated_seconds: int,
        risk_level: str,
        risks: list[str],
        human_direction_provided: bool = False,
    ) -> dict[str, Any]:
        target = self.project.get_target(run_id)
        run = self.project.get_run(run_id)
        known_expectations = {
            record["expectation_id"] for record in self.project.records(run_id, "expectations")
        }
        known_observations = {
            record["observation_id"] for record in self.project.records(run_id, "observations")
        }
        missing_expectations = sorted(set(expectation_ids) - known_expectations)
        missing_observations = sorted(set(observation_ids) - known_observations)
        if missing_expectations or missing_observations:
            raise UsageError(
                "Candidate references unknown source records.",
                details={
                    "missing_expectations": missing_expectations,
                    "missing_observations": missing_observations,
                },
            )
        candidate_id = self.project.next_id(run_id, "D", collection="discoveries")
        created_at = utc_now()
        context = read_json(self.project.paths(run_id).context)
        candidate = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": candidate_id,
            "run_id": run_id,
            "created_at": created_at,
            "state": "CANDIDATE",
            "expectation_ids": expectation_ids,
            "observation_ids": observation_ids,
            "discrepancy": discrepancy,
            "materiality_question": materiality_question,
            "origin": origin.upper(),
            "provenance": {
                "prompt_hash": context["prompt_hash"],
                "context_manifest_hash": run["context_manifest_hash"],
                "human_direction_provided": human_direction_provided,
            },
            "proposed_by": actor.to_dict(),
            "snapshot_hash": target["snapshot_hash"],
        }
        hypothesis = {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": f"H-{candidate_id[2:]}",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "created_at": created_at,
            "state": "HYPOTHESIZED",
            "main_hypothesis": main_hypothesis,
            "benign_alternatives": benign_alternatives,
            "falsification_conditions": falsification_conditions,
            "minimal_experiment": minimal_experiment,
            "expected_observations": {
                "supporting": supporting_outcomes,
                "falsifying": falsifying_outcomes,
                "inconclusive": inconclusive_outcomes,
            },
            "cost_and_risk": {
                "estimated_seconds": estimated_seconds,
                "risk_level": risk_level.upper(),
                "risks": risks,
            },
            "required_capabilities": ["EXECUTE_SANDBOX"],
            "proposed_by": actor.to_dict(),
            "snapshot_hash": target["snapshot_hash"],
        }
        return self.project.create_candidate(
            run_id, candidate=candidate, hypothesis=hypothesis, actor=actor
        )

    def plan_experiment(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        commands: list[dict[str, Any]],
        support_criteria: list[str],
        falsify_criteria: list[str],
        inconclusive_criteria: list[str],
        outcome_assertions: list[dict[str, Any]],
        wall_seconds: int,
        cpu_seconds: int,
        disk_bytes: int,
        processes: int,
        mutation_scope: str = "SANDBOX_ONLY",
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REQUEST_EXPERIMENT)
        if self.project.current_state(run_id, candidate_id) is not State.HYPOTHESIZED:
            raise PolicyError("Experiment planning requires HYPOTHESIZED state.")
        bundle = self.project.read_candidate(run_id, candidate_id)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        normalized_commands = list(commands)
        if not any(command.get("command_id") == "CMD-CAPTURE-DIFF" for command in commands):
            normalized_commands.append(
                {
                    "command_id": "CMD-CAPTURE-DIFF",
                    "argv": ["git", "diff", "--binary", "--no-ext-diff"],
                    "working_directory": ".",
                    "purpose": "Capture every sandbox-only repository mutation.",
                    "expected_observation": "A complete Git binary diff, possibly empty.",
                }
            )
        command_ids = {command.get("command_id") for command in normalized_commands}
        assertion_ids = [assertion.get("assertion_id") for assertion in outcome_assertions]
        classifications = {assertion.get("classification") for assertion in outcome_assertions}
        if (
            len(assertion_ids) != len(set(assertion_ids))
            or classifications != {"SUPPORTS", "FALSIFIES"}
            or any(
                assertion.get("command_id") not in command_ids for assertion in outcome_assertions
            )
        ):
            raise UsageError(
                "Outcome assertions require unique IDs, both classifications, and known commands."
            )
        for assertion in outcome_assertions:
            expected = assertion.get("expected")
            if assertion.get("field") == "EXIT_CODE":
                valid_expected = isinstance(expected, int) and not isinstance(expected, bool)
            else:
                valid_expected = (
                    isinstance(expected, str)
                    and len(expected) == 64
                    and expected == expected.lower()
                    and all(character in "0123456789abcdef" for character in expected)
                )
            if not valid_expected:
                raise UsageError("Outcome assertion expected value has the wrong type or digest.")
        plan = {
            "schema_version": SCHEMA_VERSION,
            "plan_id": f"P-{candidate_id[2:]}",
            "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
            "run_id": run_id,
            "created_at": utc_now(),
            "protocol_hash": run["protocol"]["sha256"],
            "snapshot_hash": target["snapshot_hash"],
            "isolation": {
                "worktree": "ISOLATED",
                "network": "DISABLED",
                "secret_free": True,
                "mutation_scope": mutation_scope.upper(),
                "limits": {
                    "cpu_seconds": cpu_seconds,
                    "wall_seconds": wall_seconds,
                    "disk_bytes": disk_bytes,
                    "processes": processes,
                },
            },
            "commands": normalized_commands,
            "outcome_criteria": {
                "support": support_criteria,
                "falsify": falsify_criteria,
                "inconclusive": inconclusive_criteria,
            },
            "outcome_assertions": outcome_assertions,
            "required_capabilities": ["EXECUTE_SANDBOX"],
            "planner": actor.to_dict(),
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/plan.json",
            plan,
            actor=actor,
            event_type="EXPERIMENT_PLANNED",
            schema_name="experiment-plan",
        )
        self.project.transition_candidate(
            run_id,
            candidate_id,
            State.TESTABLE,
            actor=actor,
            reason="A predeclared falsifiable experiment plan was frozen.",
        )
        return plan

    def _store_execution(
        self,
        *,
        run_id: str,
        target_hash: str,
        command_id: str,
        execution: dict[str, Any],
        actor: Actor,
        evidence_counter: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        stdout_meta = self.store.put_bytes(
            execution["stdout"].encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            original_name=f"{command_id}.stdout.txt",
        )
        stderr_meta = self.store.put_bytes(
            execution["stderr"].encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            original_name=f"{command_id}.stderr.txt",
        )
        record_meta = self.store.put_bytes(
            canonical_json(execution),
            media_type="application/json",
            original_name=f"{command_id}.execution.json",
        )
        common_refs = [
            stdout_meta.to_reference(),
            stderr_meta.to_reference(),
            record_meta.to_reference(schema_name="execution-record"),
        ]
        full_refs: list[dict[str, Any]] = []
        for offset, (kind, metadata) in enumerate(
            (("STDOUT", stdout_meta), ("STDERR", stderr_meta), ("COMMAND", record_meta))
        ):
            reference = {
                "schema_version": SCHEMA_VERSION,
                "evidence_id": f"EV-{evidence_counter + offset:08d}",
                "run_id": run_id,
                "kind": kind,
                "sha256": metadata.sha256,
                "uri": metadata.uri,
                "size_bytes": metadata.size,
                "media_type": metadata.media_type,
                "created_at": metadata.created_at,
                "producer": actor.to_dict(),
                "provenance": {
                    "immutable": True,
                    "target_snapshot_hash": target_hash,
                    "command_id": command_id,
                },
            }
            validate_or_raise("evidence-reference", reference)
            full_refs.append(reference)
        result_execution = {
            "command_id": command_id,
            "started_at": execution["started_at"],
            "completed_at": execution["completed_at"],
            "exit_code": execution["exit_code"] if execution["exit_code"] is not None else -1,
            "stdout_ref": stdout_meta.to_reference(),
            "stderr_ref": stderr_meta.to_reference(),
            "artifact_refs": [record_meta.to_reference(schema_name="execution-record")],
        }
        if command_id == "CMD-CAPTURE-DIFF":
            result_execution["diff_ref"] = stdout_meta.to_reference()
        return result_execution, common_refs, full_refs

    def _execute_plan(
        self,
        *,
        run_id: str,
        candidate_id: str,
        actor: Actor,
        allowed_executables: list[str],
        replay: bool,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], str]:
        root = self.project.candidate_dir(run_id, candidate_id)
        plan = read_json(root / "experiment" / "plan.json")
        target = self.project.get_target(run_id)
        all_refs: list[dict[str, Any]] = []
        result_executions: list[dict[str, Any]] = []
        evidence_records: list[dict[str, Any]] = []
        denied: str | None = None
        environment = {
            "adapter": "local_restricted",
            "fresh_git_worktree": True,
            "network_isolated": False,
            "secret_isolation": "environment-name stripping only",
            "limits_enforced": {
                "wall_seconds": True,
                "cpu_seconds": False,
                "disk_bytes": False,
                "processes": False,
            },
            "platform": platform.platform(),
            "notice": ISOLATION_NOTICE,
            "input_manifest": {
                "target_snapshot_hash": target["snapshot_hash"],
                "plan_hash": hash_json(plan),
                "allowed_executables": sorted(set(allowed_executables) | {"git"}),
            },
        }
        with temporary_worktree(
            target["repository_path"],
            target["commit"],
            require_source_clean=False,
        ) as worktree:
            executor = RestrictedExecutor(
                worktree,
                allowed_executables={*allowed_executables, "git"},
                timeout_seconds=plan["isolation"]["limits"]["wall_seconds"],
            )
            for index, command in enumerate(plan["commands"], start=1):
                started_at = utc_now()
                try:
                    execution = executor.execute(
                        command["argv"],
                        cwd=command.get("working_directory", "."),
                    )
                except UnaskedError as exc:
                    denied = f"{exc.code}: {exc.message}"
                    execution = {
                        "argv": command["argv"],
                        "cwd": command.get("working_directory", "."),
                        "stdout": "",
                        "stderr": denied,
                        "exit_code": -1,
                        "timed_out": False,
                        "isolation": "local_restricted",
                        "network_isolated": False,
                    }
                execution["started_at"] = started_at
                execution["completed_at"] = utc_now()
                execution["purpose"] = command["purpose"]
                execution["expected_observation"] = command["expected_observation"]
                result_execution, refs, full_refs = self._store_execution(
                    run_id=run_id,
                    target_hash=target["snapshot_hash"],
                    command_id=command["command_id"],
                    execution=execution,
                    actor=actor,
                    evidence_counter=(index - 1) * 3 + (100000 if replay else 0),
                )
                result_executions.append(result_execution)
                all_refs.extend(refs)
                evidence_records.extend(full_refs)
                if denied is not None:
                    break
        return result_executions, _deduplicate_refs(all_refs), environment, denied or ""

    def execute_experiment(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        allowed_executables: list[str],
    ) -> dict[str, Any]:
        require_capability(actor, Capability.EXECUTE_SANDBOX)
        if self.project.current_state(run_id, candidate_id) is not State.TESTABLE:
            raise PolicyError("Experiment execution requires TESTABLE state.")
        root = self.project.candidate_dir(run_id, candidate_id)
        plan = read_json(root / "experiment" / "plan.json")
        started_at = utc_now()
        executions, refs, environment, denied = self._execute_plan(
            run_id=run_id,
            candidate_id=candidate_id,
            actor=actor,
            allowed_executables=allowed_executables,
            replay=False,
        )
        any_timeout = any(execution["exit_code"] == -1 for execution in executions) and not denied
        any_failed = any(execution["exit_code"] != 0 for execution in executions)
        if denied:
            status = "DENIED"
        elif any_timeout:
            status = "TIMED_OUT"
        elif any_failed:
            status = "FAILED"
        else:
            status = "SUCCEEDED"
        result = {
            "schema_version": SCHEMA_VERSION,
            "result_id": f"R-{candidate_id[2:]}",
            "plan_id": plan["plan_id"],
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": utc_now(),
            "status": status,
            "observed_outcome": classify_outcome(plan["outcome_assertions"], executions),
            "environment_hash": hash_json(environment),
            "executions": executions,
            "evidence_refs": refs,
            "executor": actor.to_dict(),
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/environment.json",
            environment,
            actor=actor,
            event_type="EXECUTION_ENVIRONMENT_RECORDED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/result.json",
            result,
            actor=actor,
            event_type="EXPERIMENT_EXECUTED",
            schema_name="experiment-result",
        )
        for execution in executions:
            self.project.append_candidate_record(
                run_id,
                candidate_id,
                "experiment/commands.jsonl",
                execution,
                actor=actor,
                event_type="COMMAND_RESULT_RECORDED",
            )
        return result

    def add_review(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        review_type: str,
        conclusion: str,
        findings: list[str],
        evidence_hashes: list[str],
        tested_alternatives: list[str] | None = None,
        negative_control: str | None = None,
        semantic_variant: str | None = None,
        completeness_check: str | None = None,
        challenge_attempts: list[dict[str, Any]] | None = None,
        decision_impact: str | None = None,
    ) -> dict[str, Any]:
        normalized_type = review_type.upper()
        if normalized_type == "COUNTEREVIDENCE":
            require_capability(actor, Capability.CHALLENGE)
        elif normalized_type in {"NOVELTY", "MATERIALITY", "KNOWN_ISSUE"}:
            require_capability(actor, Capability.AUTHORIZE_VERDICT)
        else:
            raise UsageError("Unknown review type.", details={"review_type": review_type})
        review = {
            "schema_version": SCHEMA_VERSION,
            "review_id": f"REV-{normalized_type}-{candidate_id[2:]}",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "review_type": normalized_type,
            "reviewed_at": utc_now(),
            "reviewer": actor.to_dict(),
            "conclusion": conclusion.upper(),
            "findings": findings,
            "evidence_hashes": evidence_hashes,
        }
        if normalized_type == "COUNTEREVIDENCE":
            review.update(
                {
                    "tested_alternatives": tested_alternatives or [],
                    "negative_control": negative_control or "",
                    "semantic_variant": semantic_variant or "",
                    "completeness_check": completeness_check or "",
                    "challenge_attempts": challenge_attempts or [],
                }
            )
            for attempt in challenge_attempts or []:
                reference = attempt.get("result_ref", {})
                digest = reference.get("sha256", "")
                if (
                    reference.get("artifact_id") != f"sha256:{digest}"
                    or reference.get("uri") not in {None, f"cas://sha256/{digest}"}
                    or digest not in evidence_hashes
                ):
                    raise PolicyError(
                        "Challenge attempt references are not bound to evidence_hashes."
                    )
                self.store.verify_or_raise(digest)
        if normalized_type in {"NOVELTY", "KNOWN_ISSUE"}:
            review["knowledge_boundary_hash"] = self.project.get_run(run_id)[
                "knowledge_boundary_hash"
            ]
        if normalized_type == "MATERIALITY":
            review["decision_impact"] = decision_impact or ""
        validate_or_raise("review", review)
        destinations = {
            "COUNTEREVIDENCE": "counterevidence/review.json",
            "NOVELTY": "novelty.json",
            "KNOWN_ISSUE": "known-issue.json",
            "MATERIALITY": "materiality.json",
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            destinations[normalized_type],
            review,
            actor=actor,
            event_type=f"{normalized_type}_REVIEW_RECORDED",
            schema_name="review",
        )
        return review

    def replay(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        allowed_executables: list[str],
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REPLAY)
        if self.project.current_state(run_id, candidate_id) is not State.SUPPORTED:
            raise PolicyError("Independent replay requires SUPPORTED state.")
        root = self.project.candidate_dir(run_id, candidate_id)
        original = read_json(root / "experiment" / "result.json")
        started_at = utc_now()
        executions, refs, environment, denied = self._execute_plan(
            run_id=run_id,
            candidate_id=candidate_id,
            actor=actor,
            allowed_executables=allowed_executables,
            replay=True,
        )
        original_signature = [
            {
                "exit_code": item["exit_code"],
                "stdout": item["stdout_ref"]["sha256"],
                "stderr": item["stderr_ref"]["sha256"],
            }
            for item in original["executions"]
        ]
        replay_signature = [
            {
                "exit_code": item["exit_code"],
                "stdout": item["stdout_ref"]["sha256"],
                "stderr": item["stderr_ref"]["sha256"],
            }
            for item in executions
        ]
        core_match = not denied and replay_signature == original_signature
        command_records: list[dict[str, Any]] = []
        evidence_hashes: list[str] = []
        for index, execution in enumerate(executions, start=1):
            metadata = self.store.put_bytes(
                canonical_json(execution),
                media_type="application/json",
                original_name=f"replay-{index:04d}.json",
            )
            command_records.append(metadata.to_reference(schema_name="experiment-execution"))
            evidence_hashes.append(metadata.sha256)
        bundle = self.project.read_candidate(run_id, candidate_id)
        input_manifest_hash = hash_json(environment["input_manifest"])
        result = {
            "schema_version": SCHEMA_VERSION,
            "replay_id": f"RP-{candidate_id[2:]}",
            "run_id": run_id,
            "source_run_id": run_id,
            "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
            "started_at": started_at,
            "completed_at": utc_now(),
            "status": "PASS" if core_match else ("INCONCLUSIVE" if denied else "FAIL"),
            "clean_environment": True,
            "environment_hash": hash_json(environment),
            "core_result_match": core_match,
            "residual_state_detected": False,
            "command_result_refs": command_records,
            "evidence_hashes": sorted(set(evidence_hashes)),
            "reproducer": actor.to_dict(),
            "independence_attestation": {
                "no_explorer_state": True,
                "no_unrecorded_files": True,
                "input_manifest_hash": input_manifest_hash,
            },
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/environment.json",
            environment,
            actor=actor,
            event_type="REPLAY_ENVIRONMENT_RECORDED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/result.json",
            result,
            actor=actor,
            event_type="REPLAY_COMPLETED",
            schema_name="replay-result",
        )
        for execution in executions:
            self.project.append_candidate_record(
                run_id,
                candidate_id,
                "replay/commands.jsonl",
                execution,
                actor=actor,
                event_type="REPLAY_COMMAND_RECORDED",
            )
        if core_match:
            self.project.transition_candidate(
                run_id,
                candidate_id,
                State.REPRODUCED,
                actor=actor,
                reason="Independent fresh-worktree replay matched recorded core outputs.",
            )
        return result

    def import_external_replay(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        result_path: Path,
        environment_path: Path,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REPLAY)
        if self.project.current_state(run_id, candidate_id) is not State.SUPPORTED:
            raise PolicyError("Independent replay import requires SUPPORTED state.")
        result = read_json(result_path)
        environment = read_json(environment_path)
        validate_or_raise("replay-result", result)
        bundle = self.project.read_candidate(run_id, candidate_id)
        plan = read_json(
            self.project.candidate_dir(run_id, candidate_id) / "experiment" / "plan.json"
        )
        target = self.project.get_target(run_id)
        expected_input_manifest = {
            "target_snapshot_hash": target["snapshot_hash"],
            "plan_hash": hash_json(plan),
            "allowed_executables": sorted(
                {command["argv"][0] for command in plan["commands"]} | {"git"}
            ),
        }
        if any(
            (
                result["run_id"] != run_id,
                result["source_run_id"] != run_id,
                result["hypothesis_id"] != bundle["hypothesis"]["hypothesis_id"],
                result["reproducer"]["actor_id"] != actor.actor_id,
                environment.get("input_manifest") != expected_input_manifest,
                result["independence_attestation"]["input_manifest_hash"]
                != hash_json(expected_input_manifest),
            )
        ):
            raise PolicyError("External replay identity does not match this run and reproducer.")
        if result["status"] == "PASS":
            limits = environment.get("limits_enforced", {})
            if not all(
                (
                    environment.get("fresh_git_worktree") is True,
                    environment.get("network_isolated") is True,
                    environment.get("secret_isolation") == "enforced",
                    bool(limits) and all(value is True for value in limits.values()),
                )
            ):
                raise PolicyError("A passing external replay lacks enforced isolation evidence.")
            isolation = environment.get("isolation_attestation", {})
            receipt = isolation.get("receipt_ref", {})
            digest = receipt.get("sha256", "")
            receipt_valid = (
                isinstance(digest, str)
                and len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest)
                and self.store.verify(digest).valid
            )
            if not all(
                (
                    isinstance(isolation.get("issuer"), str),
                    bool(isolation.get("issuer")),
                    set(isolation.get("claims", []))
                    == {
                        "NETWORK_ISOLATED",
                        "RESOURCE_LIMITS_ENFORCED",
                        "SECRET_FREE",
                    },
                    receipt.get("artifact_id") == f"sha256:{digest}",
                    receipt.get("uri") == f"cas://sha256/{digest}",
                    receipt_valid,
                )
            ):
                raise PolicyError("A passing external replay lacks a verifiable isolation receipt.")
        if result["environment_hash"] != hash_json(environment):
            raise PolicyError(
                "External replay environment_hash does not match the imported environment."
            )
        for reference in _cas_references_for_import(result):
            self.store.verify_or_raise(reference["sha256"])
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/environment.json",
            environment,
            actor=actor,
            event_type="EXTERNAL_REPLAY_ENVIRONMENT_IMPORTED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/result.json",
            result,
            actor=actor,
            event_type="EXTERNAL_REPLAY_IMPORTED",
            schema_name="replay-result",
        )
        if result["status"] == "PASS":
            self.project.transition_candidate(
                run_id,
                candidate_id,
                State.REPRODUCED,
                actor=actor,
                reason="Externally isolated replay bundle passed schema and artifact checks.",
            )
        return result


def artifact_reference_for_file(
    store: ArtifactStore, path: Path
) -> tuple[ArtifactMetadata, dict[str, Any]]:
    metadata = store.put_file(path, media_type="application/json")
    return metadata, metadata.to_reference()


def file_sha(path: Path) -> str:
    return sha256_file(path)


def _cas_references_for_import(value: Any) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if (
            isinstance(value.get("sha256"), str)
            and isinstance(value.get("uri"), str)
            and value["uri"].startswith("cas://sha256/")
        ):
            references.append(value)
        for item in value.values():
            references.extend(_cas_references_for_import(item))
    elif isinstance(value, list):
        for item in value:
            references.extend(_cas_references_for_import(item))
    return references
