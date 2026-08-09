from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from unasked import CLAIM, __version__
from unasked.artifacts import ArtifactStore
from unasked.budget import BudgetExhausted, BudgetMeter, BudgetPolicy
from unasked.errors import IntegrityError, PolicyError, UnaskedError, UsageError
from unasked.policy import Actor, Capability, State, require_capability
from unasked.project import Project
from unasked.providers import (
    ExplorerProvider,
    ProviderResponse,
    ProviderTimeoutError,
    parse_action,
)
from unasked.records import append_jsonl
from unasked.repository import list_snapshot_files, read_snapshot_file
from unasked.schemas import validate_or_raise
from unasked.util import canonical_json, hash_json, read_json, sha256_bytes, sha256_file, utc_now
from unasked.workflow import InvestigationService


class InvestigationMode(StrEnum):
    READ_ONLY_LLM = "read_only_llm"
    LLM_TOOLS_NO_EXPERIMENT_GATE = "llm_tools_no_experiment_gate"
    EXPERIMENT_LOOP_NO_FALSIFIER = "experiment_loop_no_falsifier"
    FULL_EVIDENCE_GATED = "full_evidence_gated"


_TOOL_ACTIONS = frozenset({"LIST_FILES", "READ_FILE", "SEARCH", "HASH_TEXT"})
_ALL_ACTIONS = frozenset({*_TOOL_ACTIONS, "PROPOSE", "STOP"})
_EXPECTATION_KEYS = frozenset(
    {
        "expectation_type",
        "statement",
        "reasoning_chain",
        "source_observation_ids",
        "strength",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "observation_ids",
        "discrepancy",
        "materiality_question",
        "main_hypothesis",
        "benign_alternatives",
        "falsification_conditions",
        "minimal_experiment",
        "supporting_outcomes",
        "falsifying_outcomes",
        "inconclusive_outcomes",
        "estimated_seconds",
        "risk_level",
        "risks",
    }
)
_PLAN_REQUIRED_KEYS = frozenset(
    {
        "commands",
        "support_criteria",
        "falsify_criteria",
        "inconclusive_criteria",
        "outcome_assertions",
        "wall_seconds",
        "cpu_seconds",
        "disk_bytes",
        "processes",
    }
)


def _strict_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UsageError(f"{label} must be a JSON object.")
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing or unknown:
        raise UsageError(
            f"{label} fields are not exact.",
            details={"missing": missing, "unknown": unknown},
        )
    return value


def _validate_action(action: dict[str, Any]) -> str:
    raw_name = action.get("action")
    if not isinstance(raw_name, str):
        raise UsageError("Explorer action requires a string action field.")
    name = raw_name.upper()
    if name not in _ALL_ACTIONS:
        raise UsageError(
            "Explorer returned an unknown action.",
            details={"action": raw_name, "allowed": sorted(_ALL_ACTIONS)},
        )
    allowed_by_action = {
        "LIST_FILES": {"action", "path_prefix", "limit"},
        "READ_FILE": {"action", "path", "max_bytes"},
        "SEARCH": {"action", "query", "path_prefix", "limit"},
        "HASH_TEXT": {"action", "text"},
        "PROPOSE": {"action", "expectation", "candidate", "plan"},
        "STOP": {"action", "reason"},
    }
    unknown = sorted(set(action) - allowed_by_action[name])
    if unknown:
        raise UsageError(
            "Explorer action contains unauthorized fields.",
            details={"action": name, "unknown": unknown},
        )
    if name == "PROPOSE":
        _strict_keys(action.get("expectation"), _EXPECTATION_KEYS, "expectation")
        _strict_keys(action.get("candidate"), _CANDIDATE_KEYS, "candidate")
        plan = action.get("plan")
        if plan is not None:
            if not isinstance(plan, dict):
                raise UsageError("plan must be a JSON object or null.")
            allowed_plan = {*_PLAN_REQUIRED_KEYS, "mutation_scope"}
            missing = sorted(_PLAN_REQUIRED_KEYS - plan.keys())
            unknown_plan = sorted(plan.keys() - allowed_plan)
            if missing or unknown_plan:
                raise UsageError(
                    "plan fields are not exact.",
                    details={"missing": missing, "unknown": unknown_plan},
                )
    elif name == "STOP":
        reason = action.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason or len(reason) > 256):
            raise UsageError("STOP reason must contain 1 to 256 characters when supplied.")
    return name


@dataclass(slots=True)
class BoundedExplorer:
    project: Project
    provider: ExplorerProvider
    budget: BudgetPolicy
    mode: InvestigationMode = InvestigationMode.FULL_EVIDENCE_GATED
    clock: Callable[[], float] | None = None

    @property
    def service(self) -> InvestigationService:
        return InvestigationService(self.project)

    @property
    def store(self) -> ArtifactStore:
        return ArtifactStore(self.project.artifacts_root)

    def _assert_ready(
        self, run_id: str, *, actor: Actor, auto_execute: bool
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        require_capability(actor, Capability.OBSERVE)
        require_capability(actor, Capability.PROPOSE_CANDIDATE)
        run = self.project.get_run(run_id)
        validate_or_raise("run", run)
        target = self.project.get_target(run_id)
        ledger_report = self.project.verify_ledger(run_id)
        if not ledger_report["valid"]:
            raise IntegrityError(
                "The run ledger is invalid before investigation.", details=ledger_report
            )
        scan_path = self.project.paths(run_id).root / "knowledge-scan.json"
        if not scan_path.is_file():
            raise PolicyError("observe must complete before investigate.")
        scan = read_json(scan_path)
        validate_or_raise("knowledge-scan", scan)
        if (
            scan["run_id"] != run_id
            or scan["target_snapshot_hash"] != target["snapshot_hash"]
            or scan["knowledge_boundary_hash"] != run["knowledge_boundary_hash"]
        ):
            raise IntegrityError("The knowledge scan is not bound to this run and snapshot.")
        self.store.verify_or_raise(scan["raw_observations_ref"]["sha256"])
        scan_digest = sha256_file(scan_path)
        scan_event_bound = any(
            event["event_type"] == "KNOWLEDGE_SCAN_COMPLETED"
            and event["payload"].get("path") == "knowledge-scan.json"
            and event["payload"].get("sha256") == scan_digest
            for event in self.project.ledger(run_id).read_all()
        )
        if not scan_event_bound:
            raise IntegrityError("The knowledge scan is not bound by the run ledger.")
        snapshot_identity = {
            "commit": target["commit"],
            "tree": target["tree"],
            "submodules": target.get("submodules", []),
            "dependency_locks": target.get("dependency_locks", []),
        }
        if (
            target.get("snapshot_identity") != snapshot_identity
            or target.get("snapshot_hash") != hash_json(snapshot_identity)
            or run["target"]["repository_commit"] != target["commit"]
            or run["target"]["snapshot_hash"] != target["snapshot_hash"]
        ):
            raise IntegrityError("The run target's immutable snapshot binding is invalid.")
        if (self.project.paths(run_id).root / "investigation" / "start.json").exists():
            raise PolicyError("A run may contain only one immutable bounded investigation.")
        metadata = self.provider.metadata
        if run["model"] != {"provider": metadata["provider"], "name": metadata["model"]}:
            raise PolicyError(
                "Provider identity does not match the model frozen at init.",
                details={"run_model": run["model"], "provider": metadata},
            )
        if auto_execute and self.mode in {
            InvestigationMode.READ_ONLY_LLM,
            InvestigationMode.LLM_TOOLS_NO_EXPERIMENT_GATE,
        }:
            raise PolicyError("The selected ablation mode does not permit experiment execution.")
        return run, target

    def _request(
        self,
        run_id: str,
        *,
        run: dict[str, Any],
        target: dict[str, Any],
        inventory: list[dict[str, Any]],
        last_result: dict[str, Any] | None,
        meter: BudgetMeter,
        allowed_executables: list[str],
    ) -> dict[str, Any]:
        observations = self.project.records(run_id, "observations")[: self.budget.max_observations]
        candidates = self.project.list_candidates(run_id)
        if self.mode is InvestigationMode.READ_ONLY_LLM:
            allowed_actions = ["PROPOSE", "STOP"]
        else:
            allowed_actions = [*_TOOL_ACTIONS, "PROPOSE", "STOP"]
        experiment_allowed = self.mode in {
            InvestigationMode.EXPERIMENT_LOOP_NO_FALSIFIER,
            InvestigationMode.FULL_EVIDENCE_GATED,
        }
        return {
            "schema_version": "0.1.0",
            "task": (
                "Investigate this repository for material discrepancies. "
                "Do not assume that a discovery exists."
            ),
            "run": {
                "run_id": run_id,
                "snapshot_commit": target["commit"],
                "snapshot_hash": target["snapshot_hash"],
                "protocol_hash": run["protocol"]["sha256"],
                "model": run["model"],
                "human_steering_count": 0,
            },
            "mode": self.mode.value,
            "rules": {
                "one_action_only": True,
                "model_output_is_not_evidence": True,
                "requested_state_is_ignored": True,
                "verified_action_available": False,
                "allowed_actions": sorted(allowed_actions),
                "experiment_plan_allowed": experiment_allowed,
                "exact_outcome_assertions_required": True,
                "target_writes_forbidden": True,
                "allowed_executables": sorted(set(allowed_executables)),
            },
            "inventory": inventory[: self.budget.max_inventory_entries],
            "observations": [
                {
                    "observation_id": record["observation_id"],
                    "kind": record["kind"],
                    "statement": record["statement"],
                    "source": record["source"],
                }
                for record in observations
            ],
            "expectations": [
                {
                    "expectation_id": record["expectation_id"],
                    "statement": record["statement"],
                    "strength": record["strength"],
                }
                for record in self.project.records(run_id, "expectations")
            ],
            "candidates": candidates,
            "last_action_result": last_result,
            "budget": meter.to_dict(),
        }

    def _list_files(
        self, action: dict[str, Any], inventory: list[dict[str, Any]]
    ) -> dict[str, Any]:
        prefix = action.get("path_prefix", "")
        limit = action.get("limit", self.budget.max_inventory_entries)
        if not isinstance(prefix, str) or not isinstance(limit, int) or isinstance(limit, bool):
            raise UsageError("LIST_FILES path_prefix and limit have invalid types.")
        if len(prefix) > 512:
            raise UsageError("LIST_FILES path_prefix exceeds 512 characters.")
        if limit < 1 or limit > self.budget.max_inventory_entries:
            raise UsageError("LIST_FILES limit exceeds the frozen budget.")
        matches = [item for item in inventory if item["path"].startswith(prefix)][:limit]
        return {"action": "LIST_FILES", "path_prefix": prefix, "files": matches}

    def _read_file(
        self,
        action: dict[str, Any],
        *,
        target: dict[str, Any],
    ) -> dict[str, Any]:
        path = action.get("path")
        max_bytes = action.get("max_bytes", self.budget.max_file_bytes)
        if not isinstance(path, str):
            raise UsageError("READ_FILE path must be a string.")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
            raise UsageError("READ_FILE max_bytes must be an integer.")
        if max_bytes < 1 or max_bytes > self.budget.max_file_bytes:
            raise UsageError("READ_FILE max_bytes exceeds the frozen budget.")
        content = read_snapshot_file(target["repository_path"], target["commit"], path)
        selected = content[:max_bytes]
        try:
            text = selected.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = None
            encoding = "binary"
        metadata = self.store.put_bytes(
            selected,
            media_type="text/plain; charset=utf-8"
            if text is not None
            else "application/octet-stream",
            original_name=Path(path).name,
        )
        return {
            "action": "READ_FILE",
            "path": path,
            "encoding": encoding,
            "content": text,
            "selected_bytes": len(selected),
            "total_bytes": len(content),
            "truncated": len(selected) < len(content),
            "source_sha256": sha256_bytes(content),
            "artifact_ref": metadata.to_reference(),
        }

    def _search(
        self,
        action: dict[str, Any],
        *,
        target: dict[str, Any],
        inventory: list[dict[str, Any]],
    ) -> dict[str, Any]:
        query = action.get("query")
        prefix = action.get("path_prefix", "")
        limit = action.get("limit", self.budget.max_search_matches)
        if not isinstance(query, str) or not query or len(query) > 256:
            raise UsageError("SEARCH query must contain 1 to 256 literal characters.")
        if not isinstance(prefix, str) or not isinstance(limit, int) or isinstance(limit, bool):
            raise UsageError("SEARCH path_prefix and limit have invalid types.")
        if len(prefix) > 512:
            raise UsageError("SEARCH path_prefix exceeds 512 characters.")
        if limit < 1 or limit > self.budget.max_search_matches:
            raise UsageError("SEARCH limit exceeds the frozen budget.")
        matches: list[dict[str, Any]] = []
        for entry in inventory[: self.budget.max_inventory_entries]:
            if (
                not entry["path"].startswith(prefix)
                or entry["size_bytes"] > self.budget.max_file_bytes
            ):
                continue
            content = read_snapshot_file(target["repository_path"], target["commit"], entry["path"])
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if query.casefold() not in line.casefold():
                    continue
                matches.append(
                    {
                        "path": entry["path"],
                        "line": line_number,
                        "text": line[:500],
                        "source_sha256": sha256_bytes(content),
                    }
                )
                if len(matches) >= limit:
                    break
            if len(matches) >= limit:
                break
        metadata = self.store.put_bytes(
            canonical_json(matches),
            media_type="application/json",
            original_name="explorer-search-results.json",
        )
        return {
            "action": "SEARCH",
            "query": query,
            "path_prefix": prefix,
            "matches": matches,
            "artifact_ref": metadata.to_reference(),
        }

    def _hash_text(self, action: dict[str, Any]) -> dict[str, Any]:
        text = action.get("text")
        if not isinstance(text, str):
            raise UsageError("HASH_TEXT text must be a string.")
        encoded = text.encode("utf-8")
        if len(encoded) > self.budget.max_file_bytes:
            raise UsageError("HASH_TEXT input exceeds the frozen byte budget.")
        return {
            "action": "HASH_TEXT",
            "encoding": "utf-8",
            "size_bytes": len(encoded),
            "sha256": sha256_bytes(encoded),
        }

    def _propose(
        self,
        run_id: str,
        action: dict[str, Any],
        *,
        explorer: Actor,
        meter: BudgetMeter,
        auto_execute: bool,
        allowed_executables: list[str],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        meter.require_capacity("candidates")
        plan_payload = action.get("plan")
        if plan_payload is not None:
            if self.mode not in {
                InvestigationMode.EXPERIMENT_LOOP_NO_FALSIFIER,
                InvestigationMode.FULL_EVIDENCE_GATED,
            }:
                raise PolicyError("The selected ablation mode does not permit an experiment plan.")
            meter.require_capacity("experiments")
            commands = plan_payload["commands"]
            command_count = len(commands) + int(
                not any(command.get("command_id") == "CMD-CAPTURE-DIFF" for command in commands)
            )
            if command_count > self.budget.max_experiment_commands:
                raise BudgetExhausted("MAX_EXPERIMENT_COMMANDS")
            meter.require_wall_capacity(plan_payload["wall_seconds"] * command_count)
        expectation_payload = action["expectation"]
        expectation = self.service.add_expectation(
            run_id,
            actor=explorer,
            **expectation_payload,
        )
        candidate_payload = action["candidate"]
        bundle = self.service.propose_candidate(
            run_id,
            actor=explorer,
            expectation_ids=[expectation["expectation_id"]],
            origin="MODEL_EXPLORER",
            human_direction_provided=False,
            **candidate_payload,
        )
        meter.record("candidates")
        candidate_id = bundle["candidate"]["candidate_id"]
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "explorer-provenance.json",
            provenance,
            actor=explorer,
            event_type="EXPLORER_PROVENANCE_RECORDED",
        )
        result: dict[str, Any] = {
            "action": "PROPOSE",
            "expectation_id": expectation["expectation_id"],
            "candidate_id": candidate_id,
            "state": bundle["state"],
            "plan_created": False,
            "experiment_executed": False,
        }
        if plan_payload is None:
            return result
        plan = self.service.plan_experiment(
            run_id,
            candidate_id,
            actor=Actor(f"{explorer.actor_id}-planner", "experiment_planner"),
            **plan_payload,
        )
        meter.record("experiments")
        result["plan_created"] = True
        result["plan_id"] = plan["plan_id"]
        result["state"] = State.TESTABLE.value
        if not auto_execute:
            return result
        experiment = self.service.execute_experiment(
            run_id,
            candidate_id,
            actor=Actor(f"{explorer.actor_id}-executor", "sandbox_executor"),
            allowed_executables=allowed_executables,
        )
        result["experiment_executed"] = True
        result["experiment_status"] = experiment["status"]
        result["observed_outcome"] = experiment["observed_outcome"]
        if experiment["status"] == "SUCCEEDED" and experiment["observed_outcome"] == "SUPPORTS":
            target_state = State.SUPPORTED
            reason = "Frozen exact-value assertions classified the experiment as supporting."
        elif experiment["observed_outcome"] == "FALSIFIES":
            target_state = State.FALSIFIED
            reason = "Frozen exact-value assertions falsified the hypothesis."
        else:
            target_state = State.INCONCLUSIVE
            reason = "The bounded experiment did not produce authorized supporting evidence."
        self.project.transition_candidate(
            run_id,
            candidate_id,
            target_state,
            actor=explorer,
            reason=reason,
        )
        result["state"] = target_state.value
        return result

    def _dispatch(
        self,
        run_id: str,
        name: str,
        action: dict[str, Any],
        *,
        target: dict[str, Any],
        inventory: list[dict[str, Any]],
        explorer: Actor,
        meter: BudgetMeter,
        auto_execute: bool,
        allowed_executables: list[str],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        if name in _TOOL_ACTIONS:
            if self.mode is InvestigationMode.READ_ONLY_LLM:
                raise PolicyError("The read-only LLM ablation does not permit interactive tools.")
            meter.require_capacity("tool_calls")
            meter.require_wall_capacity()
            if name == "LIST_FILES":
                result = self._list_files(action, inventory)
            elif name == "READ_FILE":
                result = self._read_file(action, target=target)
            elif name == "SEARCH":
                result = self._search(action, target=target, inventory=inventory)
            else:
                result = self._hash_text(action)
            meter.require_wall_capacity()
            meter.record("tool_calls")
            return result
        if name == "PROPOSE":
            return self._propose(
                run_id,
                action,
                explorer=explorer,
                meter=meter,
                auto_execute=auto_execute,
                allowed_executables=allowed_executables,
                provenance=provenance,
            )
        return {"action": "STOP", "reason": action.get("reason", "PROVIDER_STOPPED")}

    def run(
        self,
        run_id: str,
        *,
        actor: Actor,
        allowed_executables: list[str] | None = None,
        auto_execute: bool = False,
    ) -> dict[str, Any]:
        run, target = self._assert_ready(run_id, actor=actor, auto_execute=auto_execute)
        allowed = list(dict.fromkeys(allowed_executables or []))
        provider_metadata = self.provider.metadata
        meter = (
            BudgetMeter(self.budget, clock=self.clock) if self.clock else BudgetMeter(self.budget)
        )
        inventory = list_snapshot_files(target["repository_path"], target["commit"])
        started_at = utc_now()
        start = {
            "schema_version": "0.1.0",
            "run_id": run_id,
            "started_at": started_at,
            "status": "UNSEALED_DEVELOPMENT",
            "mode": self.mode.value,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "provider": provider_metadata,
            "budget_policy": self.budget.to_dict(),
            "budget_policy_hash": self.budget.sha256,
            "allowed_executables": sorted(allowed),
            "auto_execute": auto_execute,
            "custody_attestation_synthesized": False,
            "claim_authorized": False,
        }
        self.project.write_run_artifact(
            run_id,
            "investigation/start.json",
            start,
            actor=actor,
            event_type="INVESTIGATION_STARTED",
        )
        turns_path = self.project.paths(run_id).root / "investigation" / "turns.jsonl"
        last_result: dict[str, Any] | None = None
        stop_reason = "PROVIDER_STOPPED"
        status = "COMPLETED"
        provider_failed = False
        turn_refs: list[dict[str, Any]] = []

        while True:
            request = self._request(
                run_id,
                run=run,
                target=target,
                inventory=inventory,
                last_result=last_result,
                meter=meter,
                allowed_executables=allowed,
            )
            request_bytes = canonical_json(request)
            exhausted = meter.exhausted_reason(next_request_bytes=len(request_bytes))
            if exhausted:
                status = "BUDGET_EXHAUSTED"
                stop_reason = exhausted
                break
            request_meta = self.store.put_bytes(
                request_bytes,
                media_type="application/json",
                original_name=f"explorer-turn-{meter.turns + 1}-request.json",
            )
            provider_error: dict[str, Any] | None = None
            remaining_before_call = meter.remaining_wall_seconds
            try:
                response = self.provider.invoke(
                    request,
                    max_output_bytes=self.budget.max_response_bytes,
                    timeout_seconds=remaining_before_call,
                )
            except UnaskedError as exc:
                budget_limited_timeout = (
                    isinstance(exc, ProviderTimeoutError)
                    and exc.details.get("timeout_source") == "investigation_budget"
                )
                provider_error = {
                    "error": "BUDGET_EXHAUSTED"
                    if budget_limited_timeout
                    else "PROVIDER_INVOCATION_FAILED",
                    "code": exc.code,
                    "message": exc.message,
                }
                response = ProviderResponse(
                    stdout=b"",
                    stderr=canonical_json(provider_error),
                    exit_code=75,
                )

            combined_response_bytes = len(response.stdout) + len(response.stderr)
            if combined_response_bytes > self.budget.max_response_bytes:
                remaining = self.budget.max_response_bytes
                bounded_stdout = response.stdout[:remaining]
                remaining -= len(bounded_stdout)
                bounded_stderr = response.stderr[:remaining]
                response = ProviderResponse(
                    stdout=bounded_stdout,
                    stderr=bounded_stderr,
                    exit_code=75,
                )
                provider_error = {
                    "error": "PROVIDER_OUTPUT_LIMIT",
                    "code": "MAX_RESPONSE_BYTES",
                }
                combined_response_bytes = len(response.stdout) + len(response.stderr)
            meter.record_provider_call(len(request_bytes), combined_response_bytes)
            response_meta = self.store.put_bytes(
                response.stdout,
                media_type="application/json",
                original_name=f"explorer-turn-{meter.turns}-response.json",
            )
            artifact_refs = [request_meta.to_reference(), response_meta.to_reference()]
            stderr_ref: dict[str, Any] | None = None
            if response.stderr:
                stderr_meta = self.store.put_bytes(
                    response.stderr,
                    media_type="text/plain; charset=utf-8",
                    original_name=f"explorer-turn-{meter.turns}-stderr.txt",
                )
                stderr_ref = stderr_meta.to_reference()
                artifact_refs.append(stderr_ref)

            action_name = "INVALID"
            action_status = "REJECTED"
            action_result: dict[str, Any]
            if provider_error is not None:
                action_result = provider_error
                if provider_error["error"] == "BUDGET_EXHAUSTED":
                    status = "BUDGET_EXHAUSTED"
                    stop_reason = "MAX_WALL_SECONDS"
                else:
                    provider_failed = True
                    status = "PROVIDER_FAILED"
                    stop_reason = str(provider_error["error"])
            elif meter.remaining_wall_seconds <= 0:
                action_result = {"error": "BUDGET_EXHAUSTED", "reason": "MAX_WALL_SECONDS"}
                status = "BUDGET_EXHAUSTED"
                stop_reason = "MAX_WALL_SECONDS"
            elif response.exit_code != 0:
                action_result = {
                    "error": "PROVIDER_EXIT_NONZERO",
                    "exit_code": response.exit_code,
                }
                provider_failed = True
                status = "PROVIDER_FAILED"
                stop_reason = "PROVIDER_EXIT_NONZERO"
            else:
                try:
                    action = parse_action(response.stdout)
                    validate_or_raise("explorer-action", action)
                    action_name = _validate_action(action)
                    provenance = {
                        "schema_version": "0.1.0",
                        "run_id": run_id,
                        "turn": meter.turns,
                        "request_ref": request_meta.to_reference(),
                        "response_ref": response_meta.to_reference(),
                        "provider": provider_metadata,
                        "budget_policy_hash": self.budget.sha256,
                        "human_direction_provided": False,
                        "model_output_is_evidence": False,
                    }
                    action_result = self._dispatch(
                        run_id,
                        action_name,
                        action,
                        target=target,
                        inventory=inventory,
                        explorer=actor,
                        meter=meter,
                        auto_execute=auto_execute,
                        allowed_executables=allowed,
                        provenance=provenance,
                    )
                    action_status = "ACCEPTED"
                except BudgetExhausted as exc:
                    action_result = {"error": "BUDGET_EXHAUSTED", "reason": exc.reason}
                    status = "BUDGET_EXHAUSTED"
                    stop_reason = exc.reason
                except (UnaskedError, AttributeError, KeyError, TypeError, ValueError) as exc:
                    action_result = {
                        "error": "ACTION_REJECTED",
                        "code": getattr(exc, "code", "SCHEMA_VALIDATION_FAILED"),
                        "message": str(exc),
                    }
            action_result_meta = self.store.put_bytes(
                canonical_json(action_result),
                media_type="application/json",
                original_name=f"explorer-turn-{meter.turns}-action-result.json",
            )
            action_result_ref = action_result_meta.to_reference()
            artifact_refs.append(action_result_ref)
            turn_refs.extend(artifact_refs)
            turn = append_jsonl(
                turns_path,
                {
                    "schema_version": "0.1.0",
                    "run_id": run_id,
                    "turn": meter.turns,
                    "occurred_at": utc_now(),
                    "request_ref": request_meta.to_reference(),
                    "response_ref": response_meta.to_reference(),
                    "stderr_ref": stderr_ref,
                    "provider_exit_code": response.exit_code,
                    "action": action_name,
                    "action_status": action_status,
                    "action_result_ref": action_result_ref,
                },
            )
            self.project.ledger(run_id).append(
                "EXPLORER_TURN_RECORDED",
                {
                    "turn": meter.turns,
                    "action": action_name,
                    "action_status": action_status,
                    "turn_record_hash": turn["record_hash"],
                },
                actor=actor.to_dict(),
                artifact_refs=artifact_refs,
            )
            last_result = action_result
            if provider_failed or status == "BUDGET_EXHAUSTED":
                break
            if action_name == "STOP" and action_status == "ACCEPTED":
                stop_reason = str(action_result.get("reason", "PROVIDER_STOPPED"))
                break

        candidates = self.project.list_candidates(run_id)
        certification_reasons = ["BENCHMARK_NOT_INDEPENDENTLY_SEALED"]
        if provider_metadata.get("certifying") is not True:
            certification_reasons.append("DEVELOPMENT_PROVIDER_NON_CERTIFYING")
        if provider_metadata.get("network_isolation_enforced") is not True:
            certification_reasons.append("PROVIDER_NETWORK_ISOLATION_UNPROVEN")
        result = {
            "schema_version": "0.1.0",
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": utc_now(),
            "status": status,
            "stop_reason": stop_reason,
            "mode": self.mode.value,
            "provider": provider_metadata,
            "budget": meter.to_dict(),
            "result": {
                "candidate_count": len(candidates),
                "candidate_states": {
                    state: sum(1 for item in candidates if item["current_state"] == state)
                    for state in sorted({item["current_state"] for item in candidates})
                },
                "verified_count": sum(
                    1 for item in candidates if item["current_state"] == State.VERIFIED.value
                ),
                "next_required_stages": [
                    "independent_falsifier",
                    "external_isolated_replay",
                    "independent_reviews",
                    "authority_verdict",
                ],
            },
            "provenance": {
                "turn_count": meter.turns,
                "turn_artifact_hashes": sorted({ref["sha256"] for ref in turn_refs}),
                "budget_policy_hash": self.budget.sha256,
                "target_snapshot_hash": target["snapshot_hash"],
                "protocol_hash": run["protocol"]["sha256"],
                "human_steering_count": 0,
            },
            "certification": {
                "status": "NON_CERTIFYING",
                "reason_codes": certification_reasons,
                "m0_demonstrated": False,
                "engineering_demo_completed": status in {"COMPLETED", "BUDGET_EXHAUSTED"},
                "allowed_claim": CLAIM,
            },
        }
        self.project.write_run_artifact(
            run_id,
            "investigation/result.json",
            result,
            actor=actor,
            event_type="INVESTIGATION_COMPLETED",
            schema_name="investigation-result",
        )
        ledger_report = self.project.verify_ledger(run_id)
        if not ledger_report["valid"]:
            raise IntegrityError(
                "Investigation ledger failed post-run verification.", details=ledger_report
            )
        result["ledger"] = ledger_report
        result["tool_version"] = __version__
        result["claim"] = CLAIM
        result["provider_failed"] = provider_failed
        return result


__all__ = ["BoundedExplorer", "InvestigationMode"]
