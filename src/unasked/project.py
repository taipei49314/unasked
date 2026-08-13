from __future__ import annotations

import json
import platform
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from unasked import PROTOCOL_VERSION, __version__
from unasked.budget import BudgetPolicy
from unasked.errors import IntegrityError, NotFoundError, PolicyError, UsageError
from unasked.index import DerivedIndex
from unasked.ledger import EventLedger
from unasked.locking import exclusive_file_lock, file_lock_held_by_current_thread
from unasked.policy import Actor, Capability, State, require_capability, require_transition
from unasked.protocol import load_protocol, protocol_hash
from unasked.records import append_jsonl, read_jsonl
from unasked.repository import capture_snapshot
from unasked.schemas import validate_or_raise
from unasked.util import hash_json, read_json, sha256_file, utc_now, write_json

SCHEMA_VERSION = "0.1.0"
_T = TypeVar("_T")


def _run_mutation(method: Callable[..., _T]) -> Callable[..., _T]:
    """Keep each public Project mutation inside the run's common lock."""

    @wraps(method)
    def wrapped(self: Project, run_id: str, *args: Any, **kwargs: Any) -> _T:
        with self.mutation(run_id):
            return method(self, run_id, *args, **kwargs)

    return wrapped


def _write_once(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise IntegrityError("Immutable run artifact already exists.", details={"path": str(path)})
    write_json(path, value)


def _snapshot_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "commit": snapshot["commit"],
        "tree": snapshot["tree"],
        "submodules": snapshot.get("submodules", []),
        "dependency_locks": snapshot.get("dependency_locks", []),
    }


def _new_run_id(commit: str, timestamp: str) -> str:
    compact = timestamp.replace("-", "").replace(":", "").replace(".", "")
    compact = compact.replace("+0000", "Z").replace("Z", "Z")
    return f"RUN-{compact}-{commit[:12]}"


def _event_actor(actor: Actor) -> dict[str, object]:
    return actor.to_dict()


@dataclass(frozen=True)
class RunPaths:
    root: Path

    @property
    def run(self) -> Path:
        return self.root / "run.json"

    @property
    def target(self) -> Path:
        return self.root / "target.json"

    @property
    def protocol(self) -> Path:
        return self.root / "protocol.json"

    @property
    def context(self) -> Path:
        return self.root / "context-manifest.json"

    @property
    def blindness(self) -> Path:
        return self.root / "blindness-attestation.json"

    @property
    def knowledge_boundary(self) -> Path:
        return self.root / "knowledge-boundary.json"

    @property
    def ledger(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def trial_preregistration(self) -> Path:
        return self.root / "trial-preregistration.json"

    @property
    def budget_policy(self) -> Path:
        return self.root / "budget-policy.json"

    @property
    def observations(self) -> Path:
        return self.root / "observations.jsonl"

    @property
    def expectations(self) -> Path:
        return self.root / "expectations.jsonl"

    @property
    def discoveries(self) -> Path:
        return self.root / "discoveries"


class Project:
    """A local evidence workspace whose mutable index is never authoritative."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.config_path = self.root / "config.json"
        self.runs_root = self.root / "runs"
        self.artifacts_root = self.root / "artifacts"
        self.index_path = self.root / "index.sqlite3"

    @property
    def index(self) -> DerivedIndex:
        return DerivedIndex(self.index_path)

    @classmethod
    def create(cls, root: str | Path) -> Project:
        project = cls(root)
        project.root.mkdir(parents=True, exist_ok=True)
        project.runs_root.mkdir(parents=True, exist_ok=True)
        project.artifacts_root.mkdir(parents=True, exist_ok=True)
        if not project.config_path.exists():
            _write_once(
                project.config_path,
                {
                    "schema_version": SCHEMA_VERSION,
                    "created_at": utc_now(),
                    "tool": {"name": "unasked", "version": __version__},
                    "truth_sources": ["JSON", "JSONL", "content-addressed artifacts"],
                    "index_authoritative": False,
                },
            )
        return project

    @classmethod
    def open(cls, root: str | Path) -> Project:
        project = cls(root)
        if not project.config_path.exists():
            raise NotFoundError(
                "UNASKED workspace is not initialized.", details={"workspace": str(project.root)}
            )
        return project

    def paths(self, run_id: str) -> RunPaths:
        path = self.runs_root / run_id
        if not path.exists():
            raise NotFoundError("Run was not found.", details={"run_id": run_id})
        return RunPaths(path)

    def create_run(
        self,
        repository: str | Path,
        *,
        commit: str,
        actor: Actor,
        protocol_path: Path | None = None,
        model_provider: str = "none",
        model_name: str = "not-configured",
        trial_preregistration: dict[str, Any] | None = None,
        budget_policy: BudgetPolicy | None = None,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.OBSERVE)
        # The immutable Git object, not mutable worktree bytes, is the target. A dirty
        # source checkout is therefore safe to ignore here and is never observed.
        snapshot = capture_snapshot(repository, commit, require_clean=False)
        protocol = load_protocol(protocol_path)
        frozen_at = utc_now()
        snapshot_hash = hash_json(_snapshot_identity(snapshot))

        context_manifest = {
            "schema_version": SCHEMA_VERSION,
            "sealed_at": frozen_at,
            "high_level_prompt": protocol["high_level_prompt"],
            "prompt_hash": hash_json(protocol["high_level_prompt"]),
            "visible_inputs": [
                {
                    "kind": "repository_snapshot",
                    "commit": snapshot["commit"],
                    "snapshot_hash": snapshot_hash,
                }
            ],
            "forbidden_inputs": [
                "problem_type",
                "target_file_hint",
                "failing_test_hint",
                "error_message_hint",
                "hidden_ground_truth",
                "evaluator",
            ],
            "human_steering_count": 0,
        }
        context_hash = hash_json(context_manifest)
        knowledge_boundary = {
            "schema_version": SCHEMA_VERSION,
            "declared_at": frozen_at,
            "snapshot_commit": snapshot["commit"],
            "categories": [
                "README and repository documentation",
                "specifications and threat models",
                "release notes and changelogs",
                "issue and known-limitation snapshots when supplied",
                "repository-local CI and build metadata",
            ],
            "scan_status": "PENDING",
            "sources": [],
            "global_novelty_claim_allowed": False,
        }
        knowledge_hash = hash_json(knowledge_boundary)
        run_id = _new_run_id(snapshot["commit"], frozen_at)
        protocol_digest = protocol_hash(protocol)
        if (trial_preregistration is None) != (budget_policy is None):
            raise UsageError("Trial preregistration and budget policy must be supplied together.")
        normalized_preregistration: dict[str, Any] | None = None
        preregistration_hash: str | None = None
        if trial_preregistration is not None and budget_policy is not None:
            normalized_preregistration = json.loads(
                json.dumps(trial_preregistration, ensure_ascii=False)
            )
            validate_or_raise("trial-preregistration", normalized_preregistration)
            expected_model = {"provider": model_provider, "name": model_name}
            binding_failures = {
                "target_commit": normalized_preregistration["target_commit"] == snapshot["commit"],
                "protocol_hash": normalized_preregistration["protocol_hash"] == protocol_digest,
                "budget_policy_hash": (
                    normalized_preregistration["budget_policy_hash"] == budget_policy.sha256
                ),
                "model": normalized_preregistration["model"] == expected_model,
            }
            failed = sorted(name for name, passed in binding_failures.items() if not passed)
            if failed:
                raise PolicyError(
                    "Trial preregistration does not match the immutable run inputs.",
                    details={"failed_bindings": failed},
                )
            preregistration_hash = hash_json(normalized_preregistration)
        target = {
            **snapshot,
            "snapshot_hash": snapshot_hash,
            "snapshot_identity": _snapshot_identity(snapshot),
        }
        run = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "created_at": frozen_at,
            "status": "CREATED",
            "target": {
                "repository_url": str(Path(repository).expanduser().resolve()),
                "repository_commit": snapshot["commit"],
                "snapshot_hash": snapshot_hash,
                "submodules_hash": hash_json(snapshot.get("submodules", [])),
                "dependency_lock_hash": hash_json(snapshot.get("dependency_locks", [])),
            },
            "protocol": {
                "version": protocol.get("protocol_version", PROTOCOL_VERSION),
                "sha256": protocol_digest,
                "frozen_at": frozen_at,
            },
            "model": {"provider": model_provider, "name": model_name},
            "tools": [
                {"name": "unasked", "version": __version__},
                {"name": "git", "version": snapshot["git_version"]},
                {"name": "python", "version": platform.python_version()},
            ],
            "context_manifest_hash": context_hash,
            "knowledge_boundary_hash": knowledge_hash,
            "human_interventions": [],
        }
        if normalized_preregistration is not None and budget_policy is not None:
            run["budget_policy_hash"] = budget_policy.sha256
            run["trial_binding"] = {
                "registration_id": normalized_preregistration["registration_id"],
                "suite_id": normalized_preregistration["suite_id"],
                "case_id": normalized_preregistration["case_id"],
                "variant": normalized_preregistration["variant"],
                "preregistration_hash": preregistration_hash,
                "manifest_hash": normalized_preregistration["manifest_hash"],
            }
        validate_or_raise("run", run)
        blindness = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "attested_at": frozen_at,
            "attested_by": actor.to_dict(),
            "no_directional_human_hint": True,
            "hidden_ground_truth_access": False,
            "evaluator_access": False,
            "human_steering_count": 0,
            "external_custody_proof_present": False,
            "note": "Self-attestation is provenance, not independent proof of blindness.",
        }
        run_root = self.runs_root / run_id
        if run_root.exists():
            raise IntegrityError("Generated run ID already exists.", details={"run_id": run_id})
        run_root.mkdir(parents=True)
        paths = RunPaths(run_root)
        with self.mutation(run_id):
            _write_once(paths.target, target)
            _write_once(paths.protocol, protocol)
            _write_once(paths.context, context_manifest)
            _write_once(paths.blindness, blindness)
            _write_once(paths.knowledge_boundary, knowledge_boundary)
            if normalized_preregistration is not None and budget_policy is not None:
                _write_once(paths.trial_preregistration, normalized_preregistration)
                _write_once(paths.budget_policy, budget_policy.to_dict())
            _write_once(paths.run, run)
            paths.discoveries.mkdir()
            run_created_payload = {
                "target_snapshot_hash": snapshot_hash,
                "protocol_hash": protocol_digest,
                "context_manifest_hash": context_hash,
                "knowledge_boundary_hash": knowledge_hash,
            }
            if normalized_preregistration is not None and budget_policy is not None:
                run_created_payload.update(
                    {
                        "trial_preregistration_hash": preregistration_hash,
                        "budget_policy_hash": budget_policy.sha256,
                    }
                )
            self.append_event(
                run_id,
                "RUN_CREATED",
                run_created_payload,
                actor=_event_actor(actor),
            )
            self.index.upsert_run(
                {
                    "run_id": run_id,
                    "created_at": frozen_at,
                    "target_commit": snapshot["commit"],
                    "protocol_hash": protocol_digest,
                    "status": "CREATED",
                }
            )
        return run

    def get_run(self, run_id: str) -> dict[str, Any]:
        return read_json(self.paths(run_id).run)

    def get_target(self, run_id: str) -> dict[str, Any]:
        return read_json(self.paths(run_id).target)

    def validate_trial_binding(
        self,
        run_id: str,
        *,
        expected_budget: BudgetPolicy | None = None,
    ) -> tuple[dict[str, Any], BudgetPolicy] | None:
        """Validate the immutable preregistration/budget pair for a trial run."""

        run = self.get_run(run_id)
        validate_or_raise("run", run)
        binding = run.get("trial_binding")
        if binding is None:
            return None
        paths = self.paths(run_id)
        preregistration = read_json(paths.trial_preregistration)
        budget_document = read_json(paths.budget_policy)
        validate_or_raise("trial-preregistration", preregistration)
        budget = BudgetPolicy.from_dict(budget_document)
        target = self.get_target(run_id)
        ledger_report = self.ledger(run_id).verify()
        ledger_events = self.ledger(run_id).read_all() if ledger_report.valid else []
        run_created_events = [
            event for event in ledger_events if event.get("event_type") == "RUN_CREATED"
        ]
        expected_run_created_payload = {
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "context_manifest_hash": run["context_manifest_hash"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "trial_preregistration_hash": binding["preregistration_hash"],
            "budget_policy_hash": run["budget_policy_hash"],
        }
        expected_binding = {
            "registration_id": preregistration["registration_id"],
            "suite_id": preregistration["suite_id"],
            "case_id": preregistration["case_id"],
            "variant": preregistration["variant"],
            "preregistration_hash": hash_json(preregistration),
            "manifest_hash": preregistration["manifest_hash"],
        }
        checks = {
            "trial_binding": binding == expected_binding,
            "budget_policy_hash": run.get("budget_policy_hash") == budget.sha256,
            "preregistration_budget": preregistration["budget_policy_hash"] == budget.sha256,
            "target_commit": preregistration["target_commit"] == target["commit"],
            "run_commit": run["target"]["repository_commit"] == target["commit"],
            "protocol_hash": preregistration["protocol_hash"] == run["protocol"]["sha256"],
            "protocol_file": protocol_hash(read_json(paths.protocol)) == run["protocol"]["sha256"],
            "model": preregistration["model"] == run["model"],
            "expected_budget": expected_budget is None or expected_budget.sha256 == budget.sha256,
            "ledger": ledger_report.valid,
            "run_created_event": len(run_created_events) == 1
            and run_created_events[0].get("sequence") == 0
            and run_created_events[0].get("payload") == expected_run_created_payload,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        if failed:
            raise IntegrityError(
                "Trial preregistration or budget binding is invalid.",
                details={"run_id": run_id, "failed_bindings": failed},
            )
        return preregistration, budget

    def list_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        if not self.runs_root.exists():
            return runs
        for path in sorted(self.runs_root.glob("*/run.json")):
            run = read_json(path)
            summary = {
                "run_id": run["run_id"],
                "created_at": run["created_at"],
                "target_commit": run["target"]["repository_commit"],
                "protocol_hash": run["protocol"]["sha256"],
                "status": run["status"],
            }
            self.index.upsert_run(summary)
            runs.append(summary)
        return runs

    def list_candidates(self, run_id: str) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for root in sorted(self.paths(run_id).discoveries.glob("D-*")):
            if not (root / "candidate.json").is_file():
                continue
            candidate = read_json(root / "candidate.json")
            state = self.current_state(run_id, candidate["candidate_id"]).value
            summary = {
                "candidate_id": candidate["candidate_id"],
                "run_id": run_id,
                "current_state": state,
                "updated_at": read_jsonl(root / "states.jsonl")[-1]["occurred_at"],
            }
            self.index.upsert_candidate(
                run_id=run_id,
                candidate_id=candidate["candidate_id"],
                state=state,
                updated_at=summary["updated_at"],
            )
            candidates.append(summary)
        return candidates

    def ledger(self, run_id: str) -> EventLedger:
        return EventLedger(self.paths(run_id).ledger, run_id=run_id)

    def mutation_lock_path(self, run_id: str) -> Path:
        return self.paths(run_id).root / ".mutation.lock"

    @contextmanager
    def mutation(self, run_id: str) -> Iterator[None]:
        """Serialize all cooperating mutations of one run evidence graph."""

        with exclusive_file_lock(self.mutation_lock_path(run_id)):
            yield

    def assert_mutation_locked(self, run_id: str) -> None:
        if not file_lock_held_by_current_thread(self.mutation_lock_path(run_id)):
            raise IntegrityError(
                "A run mutation was attempted without the common mutation lock.",
                details={"run_id": run_id},
            )

    @_run_mutation
    def append_event(
        self,
        run_id: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        actor: str | Mapping[str, Any] = "system",
        role: str = "SYSTEM",
        capabilities: Sequence[str] = (),
        occurred_at: str | None = None,
        artifact_refs: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        """Append a run event while preserving mutation-lock-before-ledger-lock order."""

        return self.ledger(run_id).append(
            event_type,
            payload,
            actor=actor,
            role=role,
            capabilities=capabilities,
            occurred_at=occurred_at,
            artifact_refs=artifact_refs,
        )

    @_run_mutation
    def append_record(
        self,
        run_id: str,
        *,
        collection: str,
        schema_name: str,
        record: dict[str, Any],
        actor: Actor,
        event_type: str,
    ) -> dict[str, Any]:
        paths = self.paths(run_id)
        collection_paths = {
            "observations": paths.observations,
            "expectations": paths.expectations,
        }
        try:
            destination = collection_paths[collection]
        except KeyError as exc:
            raise UsageError(
                "Unknown append-only collection.", details={"collection": collection}
            ) from exc
        validate_or_raise(schema_name, record)
        target = self.get_target(run_id)
        if record.get("run_id") != run_id or record.get("snapshot_hash") != target["snapshot_hash"]:
            raise PolicyError(
                "Record identity does not match the selected run snapshot.",
                details={"collection": collection, "run_id": run_id},
            )
        source_values = (
            [record["source"]] if collection == "observations" else record.get("sources", [])
        )
        if any(source.get("snapshot_hash") != target["snapshot_hash"] for source in source_values):
            raise PolicyError(
                "Record source does not match the selected run snapshot.",
                details={"collection": collection, "run_id": run_id},
            )
        enriched = append_jsonl(destination, record)
        self.append_event(
            run_id,
            event_type,
            {
                "collection": collection,
                "record_id": next(
                    (value for key, value in record.items() if key.endswith("_id")), None
                ),
                "record_hash": enriched["record_hash"],
            },
            actor=_event_actor(actor),
        )
        return enriched

    def records(self, run_id: str, collection: str) -> list[dict[str, Any]]:
        paths = self.paths(run_id)
        destinations = {
            "observations": paths.observations,
            "expectations": paths.expectations,
        }
        try:
            return read_jsonl(destinations[collection])
        except KeyError as exc:
            raise UsageError(
                "Unknown append-only collection.", details={"collection": collection}
            ) from exc

    def next_id(self, run_id: str, prefix: str, *, collection: str) -> str:
        if collection == "discoveries":
            existing = [path.name for path in self.paths(run_id).discoveries.glob(f"{prefix}-*")]
            return f"{prefix}-{len(existing) + 1:06d}"
        existing_records = self.records(run_id, collection)
        return f"{prefix}-{len(existing_records) + 1:06d}"

    def candidate_dir(self, run_id: str, candidate_id: str) -> Path:
        path = self.paths(run_id).discoveries / candidate_id
        if not path.exists():
            raise NotFoundError(
                "Candidate was not found.",
                details={"run_id": run_id, "candidate_id": candidate_id},
            )
        return path

    @_run_mutation
    def create_candidate(
        self,
        run_id: str,
        *,
        candidate: dict[str, Any],
        hypothesis: dict[str, Any],
        actor: Actor,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.PROPOSE_CANDIDATE)
        validate_or_raise("candidate", candidate)
        validate_or_raise("hypothesis", hypothesis)
        if candidate["run_id"] != run_id or hypothesis["run_id"] != run_id:
            raise UsageError("Candidate and hypothesis must belong to the selected run.")
        if hypothesis["candidate_id"] != candidate["candidate_id"]:
            raise UsageError("Hypothesis candidate_id does not match the candidate.")
        target = self.get_target(run_id)
        if any(
            (
                candidate["snapshot_hash"] != target["snapshot_hash"],
                hypothesis["snapshot_hash"] != target["snapshot_hash"],
                candidate["proposed_by"] != hypothesis["proposed_by"],
            )
        ):
            raise PolicyError("Candidate and hypothesis do not match the run snapshot.")
        root = self.paths(run_id).discoveries / candidate["candidate_id"]
        if root.exists():
            raise IntegrityError("Candidate ID already exists.")
        root.mkdir(parents=True)
        for child in (
            "experiment",
            "evidence/stdout",
            "evidence/stderr",
            "evidence/diffs",
            "evidence/artifacts",
            "counterevidence",
            "replay",
        ):
            (root / child).mkdir(parents=True)
        _write_once(root / "candidate.json", candidate)
        _write_once(root / "hypothesis.json", hypothesis)
        state_path = root / "states.jsonl"
        signal = append_jsonl(
            state_path,
            {
                "candidate_id": candidate["candidate_id"],
                "occurred_at": candidate["created_at"],
                "from": None,
                "to": State.SIGNAL.value,
                "actor": actor.to_dict(),
                "reason": "Initial signal retained before candidate registration.",
            },
        )
        candidate_state = self._transition(
            run_id,
            candidate["candidate_id"],
            State.CANDIDATE,
            actor=actor,
            reason="Sourced expectation and observation discrepancy registered.",
            current=State.SIGNAL,
        )
        hypothesized_state = self._transition(
            run_id,
            candidate["candidate_id"],
            State.HYPOTHESIZED,
            actor=actor,
            reason="Falsifiable hypothesis and benign alternative registered.",
            current=State.CANDIDATE,
        )
        self.append_event(
            run_id,
            "CANDIDATE_PROPOSED",
            {
                "candidate_id": candidate["candidate_id"],
                "candidate_hash": hash_json(candidate),
                "hypothesis_hash": hash_json(hypothesis),
                "initial_state_hash": signal["record_hash"],
                "candidate_state_hash": candidate_state["record_hash"],
                "hypothesized_state_hash": hypothesized_state["record_hash"],
            },
            actor=_event_actor(actor),
        )
        return {"candidate": candidate, "hypothesis": hypothesis, "state": "HYPOTHESIZED"}

    def current_state(self, run_id: str, candidate_id: str) -> State:
        records = read_jsonl(self.candidate_dir(run_id, candidate_id) / "states.jsonl")
        if not records:
            raise IntegrityError("Candidate has no state history.")
        return State(records[-1]["to"])

    @_run_mutation
    def transition_candidate(
        self,
        run_id: str,
        candidate_id: str,
        target: State,
        *,
        actor: Actor,
        reason: str,
    ) -> dict[str, Any]:
        if target is State.VERIFIED:
            raise PolicyError("VERIFIED may only be written by the authority kernel.")
        evidence_sha256: str | None = None
        if target is State.TESTABLE:
            plan_path = self.candidate_dir(run_id, candidate_id) / "experiment" / "plan.json"
            validate_or_raise("experiment-plan", read_json(plan_path))
            evidence_sha256 = sha256_file(plan_path)
        elif target is State.SUPPORTED:
            result_path = self.candidate_dir(run_id, candidate_id) / "experiment" / "result.json"
            result = read_json(result_path)
            validate_or_raise("experiment-result", result)
            if result["observed_outcome"] != "SUPPORTS":
                raise PolicyError(
                    "SUPPORTED requires a deterministically classified supporting experiment."
                )
            evidence_sha256 = sha256_file(result_path)
        elif target is State.REPRODUCED:
            replay_path = self.candidate_dir(run_id, candidate_id) / "replay" / "result.json"
            replay = read_json(replay_path)
            validate_or_raise("replay-result", replay)
            if replay["status"] != "PASS":
                raise PolicyError("REPRODUCED requires a passing replay result.")
            evidence_sha256 = sha256_file(replay_path)
        return self._transition(
            run_id,
            candidate_id,
            target,
            actor=actor,
            reason=reason,
            current=self.current_state(run_id, candidate_id),
            evidence_sha256=evidence_sha256,
        )

    @_run_mutation
    def authorize_verified(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        reason: str,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.AUTHORIZE_VERDICT)
        current = self.current_state(run_id, candidate_id)
        if current is not State.REPRODUCED:
            raise PolicyError(
                "Only a REPRODUCED candidate may be authorized as VERIFIED.",
                details={"current_state": current.value},
            )
        return self._transition(
            run_id,
            candidate_id,
            State.VERIFIED,
            actor=actor,
            reason=reason,
            current=current,
            evidence_sha256=sha256_file(
                self.candidate_dir(run_id, candidate_id) / "certificate.yaml"
            ),
        )

    def _transition(
        self,
        run_id: str,
        candidate_id: str,
        target: State,
        *,
        actor: Actor,
        reason: str,
        current: State,
        evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        require_transition(current, target)
        if not reason.strip():
            raise UsageError("State transition reason must not be empty.")
        capability_for_target = {
            State.CANDIDATE: Capability.PROPOSE_CANDIDATE,
            State.HYPOTHESIZED: Capability.PROPOSE_CANDIDATE,
            State.TESTABLE: Capability.REQUEST_EXPERIMENT,
            State.SUPPORTED: Capability.SUBMIT_EVIDENCE,
            State.REPRODUCED: Capability.REPLAY,
        }.get(target)
        if capability_for_target is not None:
            require_capability(actor, capability_for_target)
        record_value: dict[str, Any] = {
            "candidate_id": candidate_id,
            "occurred_at": utc_now(),
            "from": current.value,
            "to": target.value,
            "actor": actor.to_dict(),
            "reason": reason,
        }
        if evidence_sha256 is not None:
            record_value["evidence_sha256"] = evidence_sha256
        record = append_jsonl(
            self.candidate_dir(run_id, candidate_id) / "states.jsonl",
            record_value,
        )
        transition_payload = {
            "candidate_id": candidate_id,
            "from_state": current.value,
            "to_state": target.value,
            "reason": reason,
            "state_record_hash": record["record_hash"],
        }
        if evidence_sha256 is not None:
            transition_payload["evidence_sha256"] = evidence_sha256
        self.append_event(
            run_id,
            "STATE_TRANSITION",
            transition_payload,
            actor=_event_actor(actor),
        )
        self.index.upsert_candidate(
            run_id=run_id,
            candidate_id=candidate_id,
            state=target.value,
            updated_at=record["occurred_at"],
        )
        return record

    @_run_mutation
    def write_candidate_artifact(
        self,
        run_id: str,
        candidate_id: str,
        relative_path: str,
        value: dict[str, Any],
        *,
        actor: Actor,
        event_type: str,
        schema_name: str | None = None,
    ) -> dict[str, Any]:
        if relative_path.startswith(("/", "\\")) or ".." in Path(relative_path).parts:
            raise PolicyError("Candidate artifact path escapes its bundle.")
        if schema_name is not None:
            validate_or_raise(schema_name, value)
        destination = self.candidate_dir(run_id, candidate_id) / relative_path
        _write_once(destination, value)
        digest = sha256_file(destination)
        self.append_event(
            run_id,
            event_type,
            {
                "candidate_id": candidate_id,
                "path": relative_path.replace("\\", "/"),
                "sha256": digest,
            },
            actor=_event_actor(actor),
        )
        return {"path": str(destination), "sha256": digest}

    @_run_mutation
    def write_run_artifact(
        self,
        run_id: str,
        relative_path: str,
        value: dict[str, Any],
        *,
        actor: Actor,
        event_type: str,
        schema_name: str | None = None,
    ) -> dict[str, Any]:
        if relative_path.startswith(("/", "\\")) or ".." in Path(relative_path).parts:
            raise PolicyError("Run artifact path escapes its bundle.")
        if schema_name is not None:
            validate_or_raise(schema_name, value)
        destination = self.paths(run_id).root / relative_path
        _write_once(destination, value)
        digest = sha256_file(destination)
        self.append_event(
            run_id,
            event_type,
            {"path": relative_path.replace("\\", "/"), "sha256": digest},
            actor=_event_actor(actor),
        )
        return {"path": str(destination), "sha256": digest}

    @_run_mutation
    def append_candidate_record(
        self,
        run_id: str,
        candidate_id: str,
        relative_path: str,
        record: dict[str, Any],
        *,
        actor: Actor,
        event_type: str,
    ) -> dict[str, Any]:
        if relative_path.startswith(("/", "\\")) or ".." in Path(relative_path).parts:
            raise PolicyError("Candidate record path escapes its bundle.")
        destination = self.candidate_dir(run_id, candidate_id) / relative_path
        enriched = append_jsonl(destination, record)
        self.append_event(
            run_id,
            event_type,
            {
                "candidate_id": candidate_id,
                "path": relative_path.replace("\\", "/"),
                "record_hash": enriched["record_hash"],
            },
            actor=_event_actor(actor),
        )
        return enriched

    def read_candidate(self, run_id: str, candidate_id: str) -> dict[str, Any]:
        root = self.candidate_dir(run_id, candidate_id)
        return {
            "candidate": read_json(root / "candidate.json"),
            "hypothesis": read_json(root / "hypothesis.json"),
            "state": self.current_state(run_id, candidate_id).value,
            "state_history": read_jsonl(root / "states.jsonl"),
        }

    def export_ledger(self, run_id: str) -> list[dict[str, Any]]:
        return self.ledger(run_id).read_all()

    def verify_ledger(self, run_id: str) -> dict[str, Any]:
        return self.ledger(run_id).verify().to_dict()


def raw_json_from_argument(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise UsageError("Expected valid JSON.", details={"value": value}) from exc
