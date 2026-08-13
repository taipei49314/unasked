from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from unasked.artifacts import ArtifactMetadata, ArtifactStore
from unasked.attestations import (
    verify_custody_attestation,
    verify_isolation_attestation,
    verify_ledger_checkpoint,
)
from unasked.errors import ConcurrentModificationError, IntegrityError, PolicyError, UsageError
from unasked.observer import observe_repository
from unasked.outcomes import classify_outcome
from unasked.policy import (
    Actor,
    Capability,
    State,
    require_capability,
    require_distinct_actors,
    require_transition,
)
from unasked.project import SCHEMA_VERSION, Project
from unasked.protocol import AUTHORIZATION_GATES
from unasked.records import read_jsonl
from unasked.schemas import validate_or_raise
from unasked.trust import load_trust_policy, parse_strict_json, verify_dsse_statement
from unasked.util import (
    canonical_json,
    hash_json,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from unasked.workflow import capture_executions_complete

_T = TypeVar("_T")


def _consistent_authority_read(method: Callable[..., _T]) -> Callable[..., _T]:
    """Take a coherent graph snapshot under the common run mutation lock."""

    @wraps(method)
    def wrapped(
        self: AuthorityKernel, run_id: str, candidate_id: str, *args: Any, **kwargs: Any
    ) -> _T:
        with self.project.mutation(run_id):
            return method(self, run_id, candidate_id, *args, **kwargs)

    return wrapped


@dataclass(frozen=True)
class GateReport:
    eligible: bool
    checks: dict[str, bool]
    detailed_checks: dict[str, bool]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "checks": self.checks,
            "detailed_checks": self.detailed_checks,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    schema_version: str
    run_id: str
    candidate_id: str
    source_state: str
    target_state: str
    prepared_graph_sha256: str
    evidence_bundle_hash: str
    target_snapshot_hash: str
    protocol_hash: str
    knowledge_boundary_hash: str
    context_manifest_hash: str
    ledger: dict[str, Any]
    trust_policy_sha256: str
    checkpoint_envelope_sha256: str
    custody_envelope_sha256: str
    isolation_envelope_sha256: str
    required_predicate_type: str
    generated_at: str
    _graph_bytes: bytes = field(repr=False)
    _evidence_manifest_bytes: bytes = field(repr=False)
    _file_preimages: tuple[tuple[str, str, bytes], ...] = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "candidate_id": self.candidate_id,
            "source_state": self.source_state,
            "target_state": self.target_state,
            "prepared_graph_sha256": self.prepared_graph_sha256,
            "evidence_bundle_hash": self.evidence_bundle_hash,
            "target_snapshot_hash": self.target_snapshot_hash,
            "protocol_hash": self.protocol_hash,
            "knowledge_boundary_hash": self.knowledge_boundary_hash,
            "context_manifest_hash": self.context_manifest_hash,
            "ledger": dict(self.ledger),
            "trust_policy_sha256": self.trust_policy_sha256,
            "checkpoint_envelope_sha256": self.checkpoint_envelope_sha256,
            "custody_envelope_sha256": self.custody_envelope_sha256,
            "isolation_envelope_sha256": self.isolation_envelope_sha256,
            "required_predicate_type": self.required_predicate_type,
            "generated_at": self.generated_at,
        }

    @property
    def prepared_graph_bytes(self) -> bytes:
        return self._graph_bytes

    @property
    def evidence_manifest_bytes(self) -> bytes:
        return self._evidence_manifest_bytes

    @property
    def file_preimages(self) -> tuple[tuple[str, str, bytes], ...]:
        return self._file_preimages

    def stable_dict(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("generated_at")
        return value

    def signing_request(self) -> dict[str, Any]:
        return {
            **self.stable_dict(),
            "subject": {
                "digest": {"sha256": self.prepared_graph_sha256},
                "media_type": "application/vnd.unasked.authorization-graph+json",
            },
        }


@dataclass(frozen=True, slots=True)
class PreparedAuthorization:
    request: AuthorizationRequest
    authority_envelope_sha256: str
    authority_payload_sha256: str
    checkpoint_envelope_sha256: str
    checkpoint_payload_sha256: str
    custody_envelope_sha256: str
    custody_payload_sha256: str
    isolation_envelope_sha256: str
    isolation_payload_sha256: str
    stable_file_descriptors: tuple[tuple[str, str, int, int, int, int, int, int, int], ...]
    _gate_report: GateReport = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "authority_envelope_sha256": self.authority_envelope_sha256,
            "authority_payload_sha256": self.authority_payload_sha256,
            "checkpoint_envelope_sha256": self.checkpoint_envelope_sha256,
            "checkpoint_payload_sha256": self.checkpoint_payload_sha256,
            "custody_envelope_sha256": self.custody_envelope_sha256,
            "custody_payload_sha256": self.custody_payload_sha256,
            "isolation_envelope_sha256": self.isolation_envelope_sha256,
            "isolation_payload_sha256": self.isolation_payload_sha256,
            "stable_file_descriptors": [
                {"path": descriptor[0], "sha256": descriptor[1], "size": descriptor[2]}
                for descriptor in self.stable_file_descriptors
            ],
        }


def _optional_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = read_json(path)
    return value if isinstance(value, dict) else None


def _without_record_hash(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "record_hash"}


def _state_history_valid(project: Project, run_id: str, candidate_id: str) -> bool:
    try:
        records = read_jsonl(project.candidate_dir(run_id, candidate_id) / "states.jsonl")
        if not records or records[0]["from"] is not None or records[0]["to"] != "SIGNAL":
            return False
        events = project.ledger(run_id).read_all()
        transition_events = [
            event
            for event in events
            if event["event_type"] == "STATE_TRANSITION"
            and event["payload"].get("candidate_id") == candidate_id
        ]
        if len(transition_events) != len(records) - 1:
            return False
        current = State.SIGNAL
        for record, event in zip(records[1:], transition_events, strict=True):
            if record["from"] != current.value:
                return False
            target = State(record["to"])
            require_transition(current, target)
            if event["actor"] != record["actor"]:
                return False
            expected_payload = {
                "candidate_id": candidate_id,
                "from_state": record["from"],
                "to_state": record["to"],
                "reason": record["reason"],
                "state_record_hash": record["record_hash"],
            }
            if "evidence_sha256" in record:
                expected_payload["evidence_sha256"] = record["evidence_sha256"]
            if event["payload"] != expected_payload:
                return False
            current = target
        candidate = read_json(project.candidate_dir(run_id, candidate_id) / "candidate.json")
        hypothesis = read_json(project.candidate_dir(run_id, candidate_id) / "hypothesis.json")
        proposed_events = [
            event
            for event in events
            if event["event_type"] == "CANDIDATE_PROPOSED"
            and event["payload"].get("candidate_id") == candidate_id
        ]
        if len(proposed_events) != 1 or len(records) < 3:
            return False
        proposed_event = proposed_events[0]
        if proposed_event["actor"] != candidate["proposed_by"]:
            return False
        if proposed_event["payload"] != {
            "candidate_id": candidate_id,
            "candidate_hash": hash_json(candidate),
            "hypothesis_hash": hash_json(hypothesis),
            "initial_state_hash": records[0]["record_hash"],
            "candidate_state_hash": records[1]["record_hash"],
            "hypothesized_state_hash": records[2]["record_hash"],
        }:
            return False
        return current in {State.REPRODUCED, State.VERIFIED}
    except Exception:
        return False


def _cas_references(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if isinstance(value.get("sha256"), str) and isinstance(value.get("artifact_id"), str):
            found.append(value)
        for item in value.values():
            found.extend(_cas_references(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_cas_references(item))
    return found


def _run_evidence_files(project: Project, run_id: str) -> dict[str, Path]:
    paths = project.paths(run_id)
    files = {
        "run": paths.run,
        "target": paths.target,
        "protocol": paths.protocol,
        "context_manifest": paths.context,
        "blindness_attestation": paths.blindness,
        "knowledge_boundary": paths.knowledge_boundary,
        "knowledge_scan": paths.root / "knowledge-scan.json",
        "custody_attestation": paths.root / "custody-attestation.json",
    }
    if project.get_run(run_id).get("trial_binding") is not None:
        files.update(
            {
                "trial_preregistration": paths.trial_preregistration,
                "budget_policy": paths.budget_policy,
            }
        )
    return files


def _expected_run_created_payload(run: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "target_snapshot_hash": target["snapshot_hash"],
        "protocol_hash": run["protocol"]["sha256"],
        "context_manifest_hash": run["context_manifest_hash"],
        "knowledge_boundary_hash": run["knowledge_boundary_hash"],
    }
    binding = run.get("trial_binding")
    if binding is not None:
        payload.update(
            {
                "trial_preregistration_hash": binding["preregistration_hash"],
                "budget_policy_hash": run["budget_policy_hash"],
            }
        )
    return payload


def _parse_time(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise UsageError(f"{field_name} must be an RFC 3339 timestamp.") from exc
    if parsed.tzinfo is None:
        raise UsageError(f"{field_name} must include a timezone.")
    return parsed.astimezone(UTC)


def _selected_time(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise UsageError("now must be timezone-aware.")
        return value.astimezone(UTC)
    return _parse_time(value, "now")


def _require_subject_sha256(statement: dict[str, Any], expected_bytes: bytes) -> None:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        raise IntegrityError("Authority Statement must contain exactly one subject.")
    digest = subjects[0].get("digest")
    actual = digest.get("sha256") if isinstance(digest, dict) else None
    expected = sha256_bytes(expected_bytes)
    if actual != expected:
        raise IntegrityError(
            "Authority Statement subject is not the prepared graph.",
            details={"expected": expected, "actual": actual},
        )


class AuthorityKernel:
    """Deterministic evidence-authorization checks; it does not infer world truth."""

    def __init__(self, project: Project) -> None:
        self.project = project
        self.store = ArtifactStore(project.artifacts_root)

    def _stable_evidence_read(
        self, path: Path, logical_name: str
    ) -> tuple[bytes, tuple[str, str, int, int, int, int, int, int, int]]:
        """Read one regular in-project file without following a symlink/reparse point."""

        project_root = self.project.root.resolve()
        try:
            relative = path.absolute().relative_to(project_root)
        except ValueError as exc:
            raise IntegrityError("Authorization evidence path escapes the project root.") from exc
        cursor = project_root
        for part in relative.parts:
            cursor = cursor / part
            try:
                metadata = cursor.lstat()
            except OSError as exc:
                raise IntegrityError(
                    "Authorization evidence file is missing or unreadable.",
                    details={"path": logical_name},
                ) from exc
            attributes = int(getattr(metadata, "st_file_attributes", 0))
            if stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
                raise IntegrityError(
                    "Authorization evidence path contains a symlink or reparse point.",
                    details={"path": logical_name},
                )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = path.lstat()
            opened = os.fstat(descriptor)
            attributes = int(getattr(opened, "st_file_attributes", 0))
            reparse_tag = int(getattr(opened, "st_reparse_tag", 0))
            if (
                not stat.S_ISREG(opened.st_mode)
                or attributes & 0x400
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise IntegrityError(
                    "Authorization evidence changed identity or is not a regular file.",
                    details={"path": logical_name},
                )
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_dev,
                opened.st_ino,
            ) != (after.st_size, after.st_mtime_ns, after.st_dev, after.st_ino):
                raise IntegrityError(
                    "Authorization evidence changed while it was being read.",
                    details={"path": logical_name},
                )
            raw = b"".join(chunks)
            return raw, (
                logical_name,
                sha256_bytes(raw),
                len(raw),
                int(after.st_dev),
                int(after.st_ino),
                int(after.st_mode),
                int(after.st_mtime_ns),
                attributes,
                reparse_tag,
            )
        finally:
            os.close(descriptor)

    def _authorization_graph(
        self,
        run_id: str,
        candidate_id: str,
    ) -> tuple[
        bytes,
        tuple[tuple[str, str, int, int, int, int, int, int, int], ...],
        tuple[tuple[str, str, bytes], ...],
        bytes,
        str,
        dict[str, Any],
    ]:
        if self.project.current_state(run_id, candidate_id) is not State.REPRODUCED:
            raise PolicyError("Authorization preparation requires source state REPRODUCED.")
        root = self.project.candidate_dir(run_id, candidate_id)
        candidate_files = {
            "candidate": root / "candidate.json",
            "hypothesis": root / "hypothesis.json",
            "experiment_plan": root / "experiment" / "plan.json",
            "experiment_result": root / "experiment" / "result.json",
            "experiment_environment": root / "experiment" / "environment.json",
            "counterevidence_review": root / "counterevidence" / "review.json",
            "replay_result": root / "replay" / "result.json",
            "replay_environment": root / "replay" / "environment.json",
            "novelty_review": root / "novelty.json",
            "known_issue_review": root / "known-issue.json",
            "materiality_review": root / "materiality.json",
            "state_history": root / "states.jsonl",
        }
        run_files = _run_evidence_files(self.project, run_id)
        collection_files = {
            "observations": self.project.paths(run_id).observations,
            "expectations": self.project.paths(run_id).expectations,
        }
        paths = {**candidate_files, **{f"run_{k}": v for k, v in run_files.items()}}
        paths.update(collection_files)
        descriptors: list[tuple[str, str, int, int, int, int, int, int, int]] = []
        preimages: list[tuple[str, str, bytes]] = []
        raw_by_name: dict[str, bytes] = {}
        referenced: set[str] = set()
        for name, path in sorted(paths.items()):
            raw, descriptor = self._stable_evidence_read(path, name)
            descriptors.append(descriptor)
            preimages.append((name, descriptor[1], raw))
            raw_by_name[name] = raw
            if path.suffix == ".json":
                document = parse_strict_json(raw)
                referenced.update(ref["sha256"] for ref in _cas_references(document))
                if isinstance(document, dict):
                    referenced.update(document.get("evidence_hashes", []))
        for digest in sorted(referenced):
            report = self.store.verify(digest)
            report.raise_for_error()
            resolved_cas = report.path.resolve()
            artifacts_root = self.project.artifacts_root.resolve()
            if artifacts_root not in resolved_cas.parents:
                raise IntegrityError("Verified CAS object escapes the project artifact root.")
            raw, descriptor = self._stable_evidence_read(report.path, f"cas:{digest}")
            descriptors.append(descriptor)
            preimages.append((f"cas:{digest}", descriptor[1], raw))
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        ledger_path = self.project.paths(run_id).ledger
        ledger_bytes, _ = self._stable_evidence_read(ledger_path, "ledger")
        ledger_report = self.project.ledger(run_id).verify(raise_on_error=True)
        ledger = {
            "entries": ledger_report.entries,
            "last_hash": ledger_report.last_hash,
            "sha256": sha256_bytes(ledger_bytes),
        }
        graph = {
            "schema_version": "0.4.0",
            "run_id": run_id,
            "candidate_id": candidate_id,
            "source_state": "REPRODUCED",
            "target_state": "VERIFIED",
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "context_manifest_hash": run["context_manifest_hash"],
            "ledger": ledger,
            "files": [
                {
                    "path": descriptor[0],
                    "sha256": descriptor[1],
                    "artifact_sha256": descriptor[1],
                    "size": descriptor[2],
                }
                for descriptor in descriptors
            ],
        }

        def reference(raw: bytes, *, media_type: str = "application/json") -> dict[str, Any]:
            digest = sha256_bytes(raw)
            return {
                "artifact_id": f"sha256:{digest}",
                "sha256": digest,
                "uri": f"cas://sha256/{digest}",
                "media_type": media_type,
                "size_bytes": len(raw),
            }

        candidate = parse_strict_json(raw_by_name["candidate"])

        def jsonl_records(name: str) -> dict[str, dict[str, Any]]:
            values: dict[str, dict[str, Any]] = {}
            identifier_field = "expectation_id" if name == "expectations" else "observation_id"
            for line in raw_by_name[name].splitlines():
                if not line:
                    continue
                document = parse_strict_json(line)
                values[document[identifier_field]] = _without_record_hash(document)
            return values

        expectations = jsonl_records("expectations")
        observations = jsonl_records("observations")
        expectation_references = [
            reference(canonical_json(expectations[identifier]))
            for identifier in candidate["expectation_ids"]
        ]
        observation_references = [
            reference(canonical_json(observations[identifier]))
            for identifier in candidate["observation_ids"]
        ]
        referenced_artifacts = [
            self.store.get_metadata(digest).to_reference() for digest in sorted(referenced)
        ]
        evidence_manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "candidate_id": candidate_id,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "ledger_last_hash": ledger["last_hash"],
            "files": {
                name: reference(raw_by_name[name])
                for name in candidate_files
                if name != "state_history"
            },
            "run_files": {name: reference(raw_by_name[f"run_{name}"]) for name in run_files},
            "expectations": expectation_references,
            "observations": observation_references,
            "referenced_artifacts": referenced_artifacts,
        }
        evidence_manifest_bytes = canonical_json(evidence_manifest)
        graph_bytes = canonical_json(graph)
        evidence_bundle_hash = sha256_bytes(evidence_manifest_bytes)
        return (
            graph_bytes,
            tuple(descriptors),
            tuple(preimages),
            evidence_manifest_bytes,
            evidence_bundle_hash,
            ledger,
        )

    @_consistent_authority_read
    def build_authorization_request(
        self,
        run_id: str,
        candidate_id: str,
        *,
        trust_policy_sha256: str,
        checkpoint_envelope_sha256: str,
        custody_envelope_sha256: str,
        isolation_envelope_sha256: str,
        generated_at: str | None = None,
    ) -> AuthorizationRequest:
        """Pure-read deterministic request for external authority/checkpoint signing."""

        graph_bytes, _, preimages, evidence_manifest_bytes, evidence_bundle_hash, ledger = (
            self._authorization_graph(run_id, candidate_id)
        )
        graph = parse_strict_json(graph_bytes)
        graph["external_attestations"] = {
            "trust_policy_sha256": trust_policy_sha256,
            "checkpoint_envelope_sha256": checkpoint_envelope_sha256,
            "custody_envelope_sha256": custody_envelope_sha256,
            "isolation_envelope_sha256": isolation_envelope_sha256,
        }
        graph_bytes = canonical_json(graph)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        return AuthorizationRequest(
            schema_version="0.4.0",
            run_id=run_id,
            candidate_id=candidate_id,
            source_state="REPRODUCED",
            target_state="VERIFIED",
            prepared_graph_sha256=sha256_bytes(graph_bytes),
            evidence_bundle_hash=evidence_bundle_hash,
            target_snapshot_hash=target["snapshot_hash"],
            protocol_hash=run["protocol"]["sha256"],
            knowledge_boundary_hash=run["knowledge_boundary_hash"],
            context_manifest_hash=run["context_manifest_hash"],
            ledger=ledger,
            trust_policy_sha256=trust_policy_sha256,
            checkpoint_envelope_sha256=checkpoint_envelope_sha256,
            custody_envelope_sha256=custody_envelope_sha256,
            isolation_envelope_sha256=isolation_envelope_sha256,
            required_predicate_type=(
                "https://schemas.unasked.dev/attestations/authority-authorization/v0.4"
            ),
            generated_at=generated_at or utc_now(),
            _graph_bytes=graph_bytes,
            _evidence_manifest_bytes=evidence_manifest_bytes,
            _file_preimages=preimages,
        )

    def _require_production_actor_separation(
        self,
        run_id: str,
        candidate_id: str,
        *,
        authority: Actor,
        custody: Any,
        isolation: Any,
        checkpoint: Any,
        signed_authority: Any,
    ) -> None:
        """Keep external trust roles separate from every evidence-producing actor."""

        root = self.project.candidate_dir(run_id, candidate_id)
        bundle = self.project.read_candidate(run_id, candidate_id)
        experiment = read_json(root / "experiment" / "result.json")
        replay = read_json(root / "replay" / "result.json")
        proposer_id = bundle["candidate"]["proposed_by"]["actor_id"]
        executor_id = experiment["executor"]["actor_id"]
        reproducer_id = replay["reproducer"]["actor_id"]
        falsifier_id = read_json(root / "counterevidence" / "review.json")["reviewer"]["actor_id"]
        core_evidence_actors = (proposer_id, executor_id, falsifier_id, reproducer_id)
        if len(set(core_evidence_actors)) != len(core_evidence_actors):
            raise PolicyError(
                "Explorer, executor, falsifier, and reproducer must be pairwise distinct."
            )
        reviewer_ids = {
            read_json(path)["reviewer"]["actor_id"]
            for path in (
                root / "counterevidence" / "review.json",
                root / "novelty.json",
                root / "known-issue.json",
                root / "materiality.json",
            )
        }
        evidence_producers = {*core_evidence_actors, *reviewer_ids}
        custodian_ids = set(custody.signer_actor_ids)
        isolation_ids = set(isolation.signer_actor_ids)
        witness_ids = set(checkpoint.signer_actor_ids)
        authority_ids = set(signed_authority.signer_actor_ids)
        if (
            custodian_ids & (evidence_producers | authority_ids)
            or isolation_ids & (evidence_producers | authority_ids)
            or witness_ids & (evidence_producers | authority_ids | custodian_ids | isolation_ids)
        ):
            raise PolicyError("Production trust roles are not separated from evidence producers.")
        if (
            authority_ids & (evidence_producers | custodian_ids | isolation_ids | witness_ids)
            or authority.actor_id not in authority_ids
        ):
            raise PolicyError("Authority signer is not separated from evidence participants.")
        if signed_authority.predicate["issuer_actor_id"] not in authority_ids:
            raise IntegrityError("Authority predicate issuer is not an authenticated signer.")
        if isolation.predicate["executor_actor_id"] != reproducer_id:
            raise IntegrityError("Isolation executor is not the replay evidence producer.")

    def evaluate(
        self,
        run_id: str,
        candidate_id: str,
        *,
        authority: Actor,
        _authenticated_custody: bool = False,
        _authenticated_isolation: bool = False,
    ) -> GateReport:
        require_capability(authority, Capability.AUTHORIZE_VERDICT)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        root = self.project.candidate_dir(run_id, candidate_id)
        bundle = self.project.read_candidate(run_id, candidate_id)
        candidate = bundle["candidate"]
        hypothesis = bundle["hypothesis"]
        validate_or_raise("run", run)
        validate_or_raise("candidate", candidate)
        validate_or_raise("hypothesis", hypothesis)
        proposer_id = candidate["proposed_by"]["actor_id"]
        reasons: list[str] = []

        blindness = _optional_json(self.project.paths(run_id).blindness) or {}
        custody = _optional_json(self.project.paths(run_id).root / "custody-attestation.json") or {}
        unasked_attestation = all(
            (
                candidate["provenance"]["human_direction_provided"] is False,
                blindness.get("no_directional_human_hint") is True,
                blindness.get("hidden_ground_truth_access") is False,
                blindness.get("evaluator_access") is False,
                blindness.get("human_steering_count") == 0,
                _authenticated_custody
                or all(
                    (
                        custody.get("sealed_before_explorer") is True,
                        custody.get("explorer_ground_truth_access") is False,
                        custody.get("directional_steering") is False,
                        custody.get("custodian", {}).get("actor_id") != proposer_id,
                    )
                ),
            )
        )

        protocol = read_json(self.project.paths(run_id).protocol)
        protocol_frozen = all(
            (
                hash_json(protocol) == run["protocol"]["sha256"],
                tuple(protocol.get("verified_requires", ())) == AUTHORIZATION_GATES,
            )
        )
        context = read_json(self.project.paths(run_id).context)
        knowledge = read_json(self.project.paths(run_id).knowledge_boundary)
        knowledge_scan = (
            _optional_json(self.project.paths(run_id).root / "knowledge-scan.json") or {}
        )
        if knowledge_scan:
            validate_or_raise("knowledge-scan", knowledge_scan)
        snapshot_bound = all(
            (
                hash_json(target["snapshot_identity"]) == target["snapshot_hash"],
                target["snapshot_hash"] == run["target"]["snapshot_hash"],
                target["commit"] == run["target"]["repository_commit"],
                hash_json(context) == run["context_manifest_hash"],
                hash_json(knowledge) == run["knowledge_boundary_hash"],
                candidate["snapshot_hash"] == target["snapshot_hash"],
                hypothesis["snapshot_hash"] == target["snapshot_hash"],
            )
        )

        observation_records = self.project.records(run_id, "observations")
        expectation_records = self.project.records(run_id, "expectations")
        for record in observation_records:
            validate_or_raise("observation", _without_record_hash(record))
        for record in expectation_records:
            validate_or_raise("expectation", _without_record_hash(record))
        observations = {record["observation_id"]: record for record in observation_records}
        expectations = {record["expectation_id"]: record for record in expectation_records}
        expectation_evidence = all(
            expectation_id in expectations and bool(expectations[expectation_id].get("sources"))
            for expectation_id in candidate["expectation_ids"]
        )
        observation_evidence = all(
            observation_id in observations for observation_id in candidate["observation_ids"]
        )
        source_replay = False
        try:
            raw_observations = observe_repository(target["repository_path"], target)
            raw_by_id = {item["observation_id"]: item for item in raw_observations}
            source_replay = all(
                observation_id in raw_by_id
                and raw_by_id[observation_id]["source"]["sha256"]
                == observations[observation_id]["source"]["sha256"]
                for observation_id in candidate["observation_ids"]
            )
        except Exception:
            source_replay = False

        falsifiable_hypothesis = all(
            (
                bool(hypothesis.get("main_hypothesis")),
                bool(hypothesis.get("benign_alternatives")),
                bool(hypothesis.get("falsification_conditions")),
                bool(hypothesis.get("minimal_experiment")),
                all(
                    bool(values) for values in hypothesis.get("expected_observations", {}).values()
                ),
            )
        )

        plan = _optional_json(root / "experiment" / "plan.json")
        experiment = _optional_json(root / "experiment" / "result.json")
        experiment_environment = _optional_json(root / "experiment" / "environment.json")
        if plan is not None:
            validate_or_raise("experiment-plan", plan)
        if experiment is not None:
            validate_or_raise("experiment-result", experiment)
        experiment_complete = (
            plan is not None
            and experiment is not None
            and experiment_environment is not None
            and experiment.get("status") == "SUCCEEDED"
            and capture_executions_complete(
                experiment.get("executions"),
                store=self.store,
                artifact_byte_limit=plan.get("isolation", {}).get("limits", {}).get("disk_bytes"),
            )
            and experiment.get("observed_outcome") == "SUPPORTS"
            and classify_outcome(
                plan.get("outcome_assertions", []), experiment.get("executions", [])
            )
            == "SUPPORTS"
        )
        discrepancy_evidence = all(
            (
                bool(candidate.get("discrepancy")),
                any(
                    expectations[identifier].get("strength") == "STRONG"
                    for identifier in candidate["expectation_ids"]
                    if identifier in expectations
                ),
                experiment_complete,
                bool(experiment.get("evidence_refs")) if experiment else False,
            )
        )
        experiment_environment_bound = (
            experiment is not None
            and experiment_environment is not None
            and experiment.get("environment_hash") == hash_json(experiment_environment)
        )

        counterevidence = _optional_json(root / "counterevidence" / "review.json") or {}
        if counterevidence:
            validate_or_raise("review", counterevidence)
        challenge_attempts = counterevidence.get("challenge_attempts", [])
        challenge_digests = [
            attempt.get("result_ref", {}).get("sha256") for attempt in challenge_attempts
        ]
        challenge_results_valid = True
        try:
            for attempt in challenge_attempts:
                result_document = read_json(self.store.get_path(attempt["result_ref"]["sha256"]))
                challenge_results_valid = challenge_results_valid and all(
                    (
                        result_document.get("schema_version") == SCHEMA_VERSION,
                        result_document.get("attempt_id") == attempt.get("attempt_id"),
                        result_document.get("attempt_type") == attempt.get("attempt_type"),
                        result_document.get("status") == "EXECUTED",
                        result_document.get("observed_outcome") == attempt.get("observed_outcome"),
                        isinstance(result_document.get("predeclared_input"), dict),
                        hash_json(result_document.get("predeclared_input"))
                        == attempt.get("predeclared_input_hash"),
                        result_document.get("predeclared_input_hash")
                        == attempt.get("predeclared_input_hash"),
                        isinstance(result_document.get("execution"), dict),
                        isinstance(result_document.get("execution", {}).get("exit_code"), int),
                    )
                )
        except Exception:
            challenge_results_valid = False
        counterevidence_complete = all(
            (
                counterevidence.get("review_type") == "COUNTEREVIDENCE",
                counterevidence.get("conclusion") == "PASS",
                bool(counterevidence.get("tested_alternatives")),
                bool(counterevidence.get("negative_control")),
                bool(counterevidence.get("semantic_variant")),
                bool(counterevidence.get("completeness_check")),
                {attempt.get("attempt_type") for attempt in challenge_attempts}
                == {
                    "BENIGN_ALTERNATIVE",
                    "NEGATIVE_CONTROL",
                    "SEMANTIC_VARIANT",
                    "COMPLETENESS_CHECK",
                },
                len(challenge_attempts) == 4,
                len({attempt.get("attempt_id") for attempt in challenge_attempts}) == 4,
                len(set(challenge_digests)) == 4,
                all(
                    attempt.get("observed_outcome") == "SURVIVED" for attempt in challenge_attempts
                ),
                set(challenge_digests).issubset(set(counterevidence.get("evidence_hashes", []))),
                challenge_results_valid,
                counterevidence.get("reviewer", {}).get("actor_id")
                not in {
                    proposer_id,
                    authority.actor_id,
                    (experiment or {}).get("executor", {}).get("actor_id"),
                },
            )
        )

        replay = _optional_json(root / "replay" / "result.json") or {}
        replay_environment = _optional_json(root / "replay" / "environment.json") or {}
        if replay:
            validate_or_raise("replay-result", replay)
        limits = replay_environment.get("limits_enforced", {})
        replay_environment_bound = (
            bool(replay)
            and bool(replay_environment)
            and replay.get("environment_hash") == hash_json(replay_environment)
        )
        expected_replay_input = (experiment_environment or {}).get("input_manifest")
        replay_input_bound = isinstance(expected_replay_input, dict) and all(
            (
                replay_environment.get("input_manifest") == expected_replay_input,
                replay.get("independence_attestation", {}).get("input_manifest_hash")
                == hash_json(expected_replay_input),
            )
        )
        replay_outputs_bound = False
        try:
            replay_documents = [
                read_json(self.store.get_path(reference["sha256"]))
                for reference in replay.get("command_result_refs", [])
            ]

            def signatures(executions: list[dict[str, Any]]) -> list[dict[str, Any]]:
                return [
                    {
                        "command_id": execution["command_id"],
                        "exit_code": execution["exit_code"],
                        "stdout": execution["stdout_ref"]["sha256"],
                        "stderr": execution["stderr_ref"]["sha256"],
                    }
                    for execution in executions
                ]

            command_digests = {
                reference["sha256"] for reference in replay.get("command_result_refs", [])
            }
            original_record_digests = {
                reference["sha256"]
                for execution in (experiment or {}).get("executions", [])
                for reference in execution.get("artifact_refs", [])
            }
            replay_outputs_bound = all(
                (
                    bool(replay_documents),
                    signatures(replay_documents)
                    == signatures((experiment or {}).get("executions", [])),
                    command_digests.issubset(set(replay.get("evidence_hashes", []))),
                    command_digests.isdisjoint(original_record_digests),
                )
            )
        except Exception:
            replay_outputs_bound = False

        # The legacy gate evaluator accepts no externally pinned trust policy.
        # External receipt bundles are retained as evidence, but this local path
        # must not infer authentication from their contents or CAS presence.
        # Treating self-declared issuer strings or CAS presence as authentication
        # would allow the evidence producer to authorize itself.
        external_isolation_attested = _authenticated_isolation
        execution_isolation_bound = external_isolation_attested or all(
            (
                replay_environment.get("fresh_git_worktree") is True,
                replay_environment.get("network_isolated") is True,
                replay_environment.get("secret_isolation") == "enforced",
                bool(limits) and all(value is True for value in limits.values()),
            )
        )
        clean_replay_passed = all(
            (
                replay.get("status") == "PASS",
                replay.get("core_result_match") is True,
                replay.get("clean_environment") is True,
                replay.get("residual_state_detected") is False,
                execution_isolation_bound,
                replay_input_bound,
                replay_outputs_bound,
                external_isolation_attested,
                replay.get("reproducer", {}).get("actor_id")
                not in {proposer_id, authority.actor_id},
            )
        )

        novelty = _optional_json(root / "novelty.json") or {}
        known_issue = _optional_json(root / "known-issue.json") or {}
        if novelty:
            validate_or_raise("review", novelty)
        if known_issue:
            validate_or_raise("review", known_issue)
        novelty_review_approved = all(
            (
                novelty.get("review_type") == "NOVELTY",
                novelty.get("conclusion") == "PASS",
                novelty.get("knowledge_boundary_hash") == run["knowledge_boundary_hash"],
                known_issue.get("review_type") == "KNOWN_ISSUE",
                known_issue.get("conclusion") == "PASS",
                known_issue.get("knowledge_boundary_hash") == run["knowledge_boundary_hash"],
            )
        )
        declared_knowledge_boundary = all(
            (
                bool(knowledge.get("categories")),
                knowledge.get("global_novelty_claim_allowed") is False,
                knowledge_scan.get("status") == "COMPLETE",
                knowledge_scan.get("knowledge_boundary_hash") == run["knowledge_boundary_hash"],
                knowledge_scan.get("target_snapshot_hash") == target["snapshot_hash"],
                knowledge_scan.get("categories") == knowledge.get("categories"),
                {hash_json(source) for source in knowledge_scan.get("source_manifest", [])}
                == {hash_json(record["source"]) for record in observation_records},
                knowledge_scan.get("raw_observations_ref", {}).get("sha256")
                in set(knowledge_scan.get("evidence_hashes", [])),
                knowledge_scan.get("scope_attestation", {}).get("repository_snapshot_fully_scanned")
                is True,
                knowledge_scan.get("scope_attestation", {}).get(
                    "supplied_external_sources_fully_scanned"
                )
                is True,
                not knowledge_scan.get("scope_attestation", {}).get("omitted_sources", []),
                novelty_review_approved,
            )
        )

        materiality = _optional_json(root / "materiality.json") or {}
        if materiality:
            validate_or_raise("review", materiality)
        materiality_review_approved = all(
            (
                materiality.get("review_type") == "MATERIALITY",
                materiality.get("conclusion") == "PASS",
                bool(materiality.get("decision_impact")),
            )
        )

        plan_data = plan or {}
        experiment_data = experiment or {}
        identity_bound = all(
            (
                run.get("run_id") == run_id,
                target.get("commit") == run["target"]["repository_commit"],
                candidate.get("candidate_id") == candidate_id,
                candidate.get("run_id") == run_id,
                hypothesis.get("candidate_id") == candidate_id,
                hypothesis.get("run_id") == run_id,
                hypothesis.get("proposed_by") == candidate.get("proposed_by"),
                candidate.get("provenance", {}).get("context_manifest_hash")
                == run["context_manifest_hash"],
                candidate.get("provenance", {}).get("prompt_hash") == context.get("prompt_hash"),
                len(observations) == len(observation_records),
                len(expectations) == len(expectation_records),
                all(
                    record.get("run_id") == run_id
                    and record.get("snapshot_hash") == target["snapshot_hash"]
                    and record.get("source", {}).get("snapshot_hash") == target["snapshot_hash"]
                    for record in observation_records
                ),
                all(
                    record.get("run_id") == run_id
                    and record.get("snapshot_hash") == target["snapshot_hash"]
                    and all(
                        source.get("snapshot_hash") == target["snapshot_hash"]
                        for source in record.get("sources", [])
                    )
                    for record in expectation_records
                ),
                plan_data.get("run_id") == run_id,
                plan_data.get("hypothesis_id") == hypothesis.get("hypothesis_id"),
                plan_data.get("protocol_hash") == run["protocol"]["sha256"],
                plan_data.get("snapshot_hash") == target["snapshot_hash"],
                experiment_data.get("run_id") == run_id,
                experiment_data.get("plan_id") == plan_data.get("plan_id"),
                replay.get("run_id") == run_id,
                replay.get("source_run_id") == run_id,
                replay.get("hypothesis_id") == hypothesis.get("hypothesis_id"),
                counterevidence.get("run_id") == run_id,
                counterevidence.get("candidate_id") == candidate_id,
                novelty.get("run_id") == run_id,
                novelty.get("candidate_id") == candidate_id,
                known_issue.get("run_id") == run_id,
                known_issue.get("candidate_id") == candidate_id,
                materiality.get("run_id") == run_id,
                materiality.get("candidate_id") == candidate_id,
                blindness.get("run_id") == run_id,
                custody.get("run_id") == run_id,
                knowledge.get("snapshot_commit") == target["commit"],
                knowledge_scan.get("run_id") == run_id,
            )
        )

        ledger_valid = self.project.ledger(run_id).verify().valid
        state_history_legal = _state_history_valid(self.project, run_id, candidate_id)
        authority_separated = all(
            (
                authority.actor_id != proposer_id,
                experiment is not None,
                experiment is not None
                and authority.actor_id != experiment.get("executor", {}).get("actor_id"),
            )
        )

        artifact_integrity = True
        integrity_documents = (
            experiment or {},
            experiment_environment or {},
            replay,
            replay_environment,
            counterevidence,
            novelty,
            known_issue,
            materiality,
            knowledge_scan,
        )
        for document in integrity_documents:
            for reference in _cas_references(document):
                digest = reference["sha256"]
                if reference["artifact_id"] != f"sha256:{digest}":
                    artifact_integrity = False
                if reference.get("uri") not in {None, f"cas://sha256/{digest}"}:
                    artifact_integrity = False
                if not self.store.verify(digest).valid:
                    artifact_integrity = False
        for document in (
            replay,
            counterevidence,
            novelty,
            known_issue,
            materiality,
            knowledge_scan,
        ):
            for digest in document.get("evidence_hashes", []):
                if not self.store.verify(digest).valid:
                    artifact_integrity = False

        detailed = {
            "unasked_attestation": unasked_attestation,
            "declared_knowledge_boundary": declared_knowledge_boundary,
            "expectation_evidence": expectation_evidence,
            "observation_evidence": observation_evidence,
            "discrepancy_evidence": discrepancy_evidence,
            "falsifiable_hypothesis": falsifiable_hypothesis,
            "experiment_complete": experiment_complete,
            "experiment_environment_bound": experiment_environment_bound,
            "counterevidence_complete": counterevidence_complete,
            "clean_replay_passed": clean_replay_passed,
            "replay_environment_bound": replay_environment_bound,
            "replay_input_bound": replay_input_bound,
            "replay_outputs_bound": replay_outputs_bound,
            "external_isolation_attested": external_isolation_attested,
            "novelty_review_approved": novelty_review_approved,
            "materiality_review_approved": materiality_review_approved,
            "artifact_integrity": artifact_integrity,
            "source_replay": source_replay,
            "ledger_integrity": ledger_valid,
            "legal_state_history": state_history_legal,
            "protocol_frozen": protocol_frozen,
            "snapshot_bound": snapshot_bound,
            "identity_bound": identity_bound,
            "independent_authority": authority_separated,
        }
        checks = {
            "snapshot_bound": snapshot_bound,
            "evidence_complete": all(
                (
                    expectation_evidence,
                    observation_evidence,
                    discrepancy_evidence,
                    falsifiable_hypothesis,
                    experiment_complete,
                )
            ),
            "clean_replay_passed": clean_replay_passed,
            "counterevidence_completed": counterevidence_complete,
            "known_issue_scan_completed": declared_knowledge_boundary,
            "protocol_frozen": protocol_frozen,
            "hashes_consistent": all(
                (
                    artifact_integrity,
                    experiment_environment_bound,
                    replay_environment_bound,
                    replay_input_bound,
                    replay_outputs_bound,
                    external_isolation_attested,
                    source_replay,
                    ledger_valid,
                    state_history_legal,
                    identity_bound,
                )
            ),
            "authority_separated": authority_separated,
            "materiality_approved": materiality_review_approved,
        }
        for name, passed in detailed.items():
            if not passed:
                reasons.append(f"Gate failed: {name}")
        return GateReport(
            eligible=tuple(detailed) == AUTHORIZATION_GATES and all(detailed.values()),
            checks=checks,
            detailed_checks=detailed,
            reasons=tuple(reasons or ["All deterministic authorization gates passed."]),
        )

    def _store_json_file(self, path: Path, *, schema_name: str | None = None) -> ArtifactMetadata:
        return self.store.put_file(path, media_type="application/json", original_name=path.name)

    @_consistent_authority_read
    def prepare_authorization(
        self,
        run_id: str,
        candidate_id: str,
        *,
        authority: Actor,
        authority_envelope_bytes: bytes,
        checkpoint_envelope_bytes: bytes,
        custody_envelope_bytes: bytes,
        isolation_envelope_bytes: bytes,
        trust_policy_bytes: bytes,
        trust_policy_sha256: str,
        manifest_bytes: bytes,
        isolation_result_bytes: bytes,
        now: datetime | str | None = None,
    ) -> PreparedAuthorization:
        """Pure-read verification of a complete externally authenticated authorization."""

        require_capability(authority, Capability.AUTHORIZE_VERDICT)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        binding = run.get("trial_binding")
        if not isinstance(binding, dict):
            raise PolicyError("Authority v2 requires a preregistered trial run.")
        replay_path = self.project.candidate_dir(run_id, candidate_id) / "replay" / "result.json"
        current_replay_bytes, _ = self._stable_evidence_read(replay_path, "replay_result_subject")
        if current_replay_bytes != isolation_result_bytes:
            raise IntegrityError("Isolation subject bytes are not the current replay result bytes.")
        policy = load_trust_policy(trust_policy_bytes, expected_sha256=trust_policy_sha256, now=now)
        if policy.mode != "PRODUCTION":
            raise PolicyError("Authority v2 requires a PRODUCTION trust policy.")
        if sha256_bytes(manifest_bytes) != binding["manifest_hash"]:
            raise IntegrityError("Custody manifest bytes do not match the preregistered manifest.")
        custody = verify_custody_attestation(
            custody_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            manifest_bytes=manifest_bytes,
            expected_suite_id=binding["suite_id"],
            expected_manifest_sha256=binding["manifest_hash"],
            now=now,
        )
        isolation = verify_isolation_attestation(
            isolation_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            result_bytes=isolation_result_bytes,
            expected_suite_id=binding["suite_id"],
            expected_case_id=binding["case_id"],
            expected_variant=binding["variant"],
            expected_run_id=run_id,
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=run["protocol"]["sha256"],
            now=now,
        )
        if not custody.production_qualified or not isolation.production_qualified:
            raise PolicyError("Custody and isolation inputs must be production-qualified.")

        checkpoint_digest = sha256_bytes(checkpoint_envelope_bytes)
        request = self.build_authorization_request(
            run_id,
            candidate_id,
            trust_policy_sha256=trust_policy_sha256,
            checkpoint_envelope_sha256=checkpoint_digest,
            custody_envelope_sha256=sha256_bytes(custody_envelope_bytes),
            isolation_envelope_sha256=sha256_bytes(isolation_envelope_bytes),
        )
        checkpoint = verify_ledger_checkpoint(
            checkpoint_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            ledger_bytes=self._stable_evidence_read(
                self.project.paths(run_id).ledger, "checkpoint_ledger"
            )[0],
            expected_suite_id=binding["suite_id"],
            expected_case_id=binding["case_id"],
            expected_variant=binding["variant"],
            expected_run_id=run_id,
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=run["protocol"]["sha256"],
            now=now,
        )
        authority_type = request.required_predicate_type
        signed_authority = verify_dsse_statement(
            authority_envelope_bytes,
            expected_predicate_type=authority_type,
            trusted_keys=policy.keys_for(authority_type),
            threshold=policy.threshold_for(authority_type),
            predicate_schema="authority-authorization-predicate",
        )
        _require_subject_sha256(signed_authority.statement, request.prepared_graph_bytes)
        predicate = signed_authority.predicate
        expected = {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "context_manifest_hash": run["context_manifest_hash"],
            "evidence_bundle_hash": request.evidence_bundle_hash,
            "ledger_checkpoint_envelope_sha256": checkpoint_digest,
            "custody_envelope_sha256": request.custody_envelope_sha256,
            "isolation_envelope_sha256": request.isolation_envelope_sha256,
            "prepared_graph_sha256": request.prepared_graph_sha256,
            "decision": "AUTHORIZE_VERIFIED",
            "authorized_state": "VERIFIED",
            "trust_policy_sha256": trust_policy_sha256,
            "issuer_actor_id": authority.actor_id,
        }
        for field_name, value in expected.items():
            if predicate[field_name] != value:
                raise IntegrityError(
                    "Signed authority predicate does not match the prepared graph.",
                    details={"field": field_name},
                )
        selected_now = _selected_time(now)
        if _parse_time(predicate["expires_at"], "expires_at") < selected_now:
            raise PolicyError("Signed authority authorization is expired.")
        if signed_authority.trust_mode != "PRODUCTION" or not signed_authority.production_qualified:
            raise PolicyError("Signed authority input is not production-qualified.")
        self._require_production_actor_separation(
            run_id,
            candidate_id,
            authority=authority,
            custody=custody,
            isolation=isolation,
            checkpoint=checkpoint,
            signed_authority=signed_authority,
        )

        report = self.evaluate(
            run_id,
            candidate_id,
            authority=authority,
            _authenticated_custody=True,
            _authenticated_isolation=True,
        )
        if not report.eligible:
            raise PolicyError(
                "Candidate evidence graph still fails authorization gates.",
                details=report.to_dict(),
            )
        _, descriptors, _, _, _, _ = self._authorization_graph(run_id, candidate_id)
        return PreparedAuthorization(
            request=request,
            authority_envelope_sha256=sha256_bytes(authority_envelope_bytes),
            authority_payload_sha256=signed_authority.payload_sha256,
            checkpoint_envelope_sha256=checkpoint_digest,
            checkpoint_payload_sha256=checkpoint.payload_sha256,
            custody_envelope_sha256=sha256_bytes(custody_envelope_bytes),
            custody_payload_sha256=custody.payload_sha256,
            isolation_envelope_sha256=sha256_bytes(isolation_envelope_bytes),
            isolation_payload_sha256=isolation.payload_sha256,
            stable_file_descriptors=descriptors,
            _gate_report=report,
        )

    def commit_authorization(
        self,
        prepared: PreparedAuthorization,
        *,
        authority: Actor,
        authority_envelope_bytes: bytes,
        checkpoint_envelope_bytes: bytes,
        custody_envelope_bytes: bytes,
        isolation_envelope_bytes: bytes,
        trust_policy_bytes: bytes,
        trust_policy_sha256: str,
        manifest_bytes: bytes,
        isolation_result_bytes: bytes,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Atomically serialize one VERIFIED transition against a prepared C_pre graph."""

        if not isinstance(prepared, PreparedAuthorization):
            raise UsageError("commit_authorization requires a PreparedAuthorization.")
        run_id = prepared.request.run_id
        candidate_id = prepared.request.candidate_id
        root = self.project.candidate_dir(run_id, candidate_id)
        marker_path = root / "authorization-commit.json"
        with self.project.mutation(run_id):
            output_paths = (root / "verdict.json", root / "certificate.yaml", marker_path)
            if (
                any(path.exists() for path in output_paths)
                or self.project.current_state(run_id, candidate_id) is not State.REPRODUCED
            ):
                raise ConcurrentModificationError(
                    "Authorization was already committed or the source state changed."
                )
            try:
                rebuilt = self.prepare_authorization(
                    run_id,
                    candidate_id,
                    authority=authority,
                    authority_envelope_bytes=authority_envelope_bytes,
                    checkpoint_envelope_bytes=checkpoint_envelope_bytes,
                    custody_envelope_bytes=custody_envelope_bytes,
                    isolation_envelope_bytes=isolation_envelope_bytes,
                    trust_policy_bytes=trust_policy_bytes,
                    trust_policy_sha256=trust_policy_sha256,
                    manifest_bytes=manifest_bytes,
                    isolation_result_bytes=isolation_result_bytes,
                    now=now,
                )
            except (IntegrityError, PolicyError) as exc:
                current_graph = self.build_authorization_request(
                    run_id,
                    candidate_id,
                    trust_policy_sha256=trust_policy_sha256,
                    checkpoint_envelope_sha256=sha256_bytes(checkpoint_envelope_bytes),
                    custody_envelope_sha256=sha256_bytes(custody_envelope_bytes),
                    isolation_envelope_sha256=sha256_bytes(isolation_envelope_bytes),
                ).prepared_graph_sha256
                if current_graph != prepared.request.prepared_graph_sha256:
                    raise ConcurrentModificationError(
                        "Prepared authorization evidence changed before commit.",
                        details={
                            "prepared": prepared.request.prepared_graph_sha256,
                            "current": current_graph,
                        },
                    ) from exc
                raise
            stable_matches = all(
                (
                    rebuilt.request.prepared_graph_sha256 == prepared.request.prepared_graph_sha256,
                    rebuilt.request.evidence_bundle_hash == prepared.request.evidence_bundle_hash,
                    rebuilt.request.ledger == prepared.request.ledger,
                    rebuilt.stable_file_descriptors == prepared.stable_file_descriptors,
                    rebuilt.authority_envelope_sha256 == prepared.authority_envelope_sha256,
                    rebuilt.authority_payload_sha256 == prepared.authority_payload_sha256,
                    rebuilt.checkpoint_envelope_sha256 == prepared.checkpoint_envelope_sha256,
                    rebuilt.checkpoint_payload_sha256 == prepared.checkpoint_payload_sha256,
                    rebuilt.custody_envelope_sha256 == prepared.custody_envelope_sha256,
                    rebuilt.custody_payload_sha256 == prepared.custody_payload_sha256,
                    rebuilt.isolation_envelope_sha256 == prepared.isolation_envelope_sha256,
                    rebuilt.isolation_payload_sha256 == prepared.isolation_payload_sha256,
                )
            )
            if not stable_matches:
                raise ConcurrentModificationError(
                    "Prepared authorization evidence changed before commit."
                )
            c_pre_bytes, _ = self._stable_evidence_read(
                self.project.paths(run_id).ledger, "c_pre_ledger"
            )
            stored_artifacts = {}
            for artifact_name, data, original_name in (
                (
                    "prepared_graph",
                    prepared.request.prepared_graph_bytes,
                    "authorization-graph.json",
                ),
                (
                    "evidence_manifest",
                    prepared.request.evidence_manifest_bytes,
                    f"{candidate_id}.evidence-manifest.json",
                ),
                ("c_pre", c_pre_bytes, "c-pre-ledger.jsonl"),
                ("authority_envelope", authority_envelope_bytes, "authority-envelope.dsse.json"),
                (
                    "checkpoint_envelope",
                    checkpoint_envelope_bytes,
                    "checkpoint-envelope.dsse.json",
                ),
                ("custody_envelope", custody_envelope_bytes, "custody-envelope.dsse.json"),
                (
                    "isolation_envelope",
                    isolation_envelope_bytes,
                    "isolation-envelope.dsse.json",
                ),
            ):
                stored_artifacts[artifact_name] = self.store.put_bytes(
                    data,
                    media_type=(
                        "application/json" if artifact_name != "c_pre" else "application/x-ndjson"
                    ),
                    original_name=original_name,
                )
            for logical_name, expected_digest, data in prepared.request.file_preimages:
                if logical_name.startswith("cas:"):
                    self.store.verify_or_raise(expected_digest)
                    continue
                preimage_meta = self.store.put_bytes(
                    data,
                    media_type=(
                        "application/x-ndjson"
                        if logical_name in {"state_history", "observations", "expectations"}
                        else "application/json"
                    ),
                    original_name=f"{logical_name.replace(':', '-')}.preimage",
                )
                if preimage_meta.sha256 != expected_digest:
                    raise ConcurrentModificationError(
                        "Prepared evidence preimage changed before authorization commit.",
                        details={"path": logical_name},
                    )
            graph_meta = stored_artifacts["prepared_graph"]
            if (
                graph_meta.sha256 != prepared.request.prepared_graph_sha256
                or stored_artifacts["evidence_manifest"].sha256
                != prepared.request.evidence_bundle_hash
                or stored_artifacts["c_pre"].sha256 != prepared.request.ledger["sha256"]
            ):
                raise ConcurrentModificationError(
                    "Prepared graph or C_pre changed before authorization commit."
                )
            result = self.authorize(
                run_id,
                candidate_id,
                authority=authority,
                _gate_report=rebuilt._gate_report,
                _authenticated_v2=True,
                _evidence_manifest_bytes=prepared.request.evidence_manifest_bytes,
                _expected_evidence_bundle_hash=prepared.request.evidence_bundle_hash,
            )
            post_report = self.project.ledger(run_id).verify(raise_on_error=True)
            state_record = self.project.read_candidate(run_id, candidate_id)["state_history"][-1]
            committed_at = (
                utc_now()
                if now is None
                else (
                    now
                    if isinstance(now, str)
                    else now.astimezone(UTC).isoformat().replace("+00:00", "Z")
                )
            )
            marker = {
                "schema_version": "0.4.0",
                "run_id": run_id,
                "candidate_id": candidate_id,
                "prepared_graph_sha256": prepared.request.prepared_graph_sha256,
                "prepared_graph_artifact_sha256": graph_meta.sha256,
                "evidence_bundle_hash": prepared.request.evidence_bundle_hash,
                "trust_policy_sha256": prepared.request.trust_policy_sha256,
                "checkpoint_envelope_sha256": prepared.checkpoint_envelope_sha256,
                "checkpoint_payload_sha256": prepared.checkpoint_payload_sha256,
                "custody_envelope_sha256": prepared.custody_envelope_sha256,
                "custody_payload_sha256": prepared.custody_payload_sha256,
                "isolation_envelope_sha256": prepared.isolation_envelope_sha256,
                "isolation_payload_sha256": prepared.isolation_payload_sha256,
                "authority_envelope_sha256": prepared.authority_envelope_sha256,
                "authority_payload_sha256": prepared.authority_payload_sha256,
                "c_pre": dict(prepared.request.ledger),
                "verdict_sha256": sha256_file(root / "verdict.json"),
                "certificate_sha256": sha256_file(root / "certificate.yaml"),
                "state_record_hash": state_record["record_hash"],
                "post_ledger_entries_before_marker": post_report.entries,
                "post_ledger_head_before_marker": post_report.last_hash,
                "committed_at": committed_at,
            }
            validate_or_raise("authorization-commit", marker)
            self.project.write_candidate_artifact(
                run_id,
                candidate_id,
                "authorization-commit.json",
                marker,
                actor=authority,
                event_type="AUTHORIZATION_COMMITTED",
                schema_name="authorization-commit",
            )
            result["authorization_commit"] = marker
            return result

    def authorize(
        self,
        run_id: str,
        candidate_id: str,
        *,
        authority: Actor,
        _gate_report: GateReport | None = None,
        _authenticated_v2: bool = False,
        _evidence_manifest_bytes: bytes | None = None,
        _expected_evidence_bundle_hash: str | None = None,
    ) -> dict[str, Any]:
        require_capability(authority, Capability.AUTHORIZE_VERDICT)
        if not _authenticated_v2:
            raise PolicyError(
                "Legacy authorization is not authorized: it is non-authenticated and cannot "
                "create VERIFIED; "
                "use Authority v2 prepare/commit with externally authenticated attestations."
            )
        bundle = self.project.read_candidate(run_id, candidate_id)
        candidate = bundle["candidate"]
        proposer_id = candidate["proposed_by"]["actor_id"]
        require_distinct_actors(proposer_id, authority.actor_id)
        report = _gate_report or self.evaluate(run_id, candidate_id, authority=authority)
        if not report.eligible:
            raise PolicyError(
                "Candidate is not authorized for VERIFIED.",
                details=report.to_dict(),
            )

        root = self.project.candidate_dir(run_id, candidate_id)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        hypothesis = bundle["hypothesis"]
        files = {
            "candidate": root / "candidate.json",
            "hypothesis": root / "hypothesis.json",
            "experiment_plan": root / "experiment" / "plan.json",
            "experiment_result": root / "experiment" / "result.json",
            "experiment_environment": root / "experiment" / "environment.json",
            "counterevidence_review": root / "counterevidence" / "review.json",
            "replay_result": root / "replay" / "result.json",
            "replay_environment": root / "replay" / "environment.json",
            "novelty_review": root / "novelty.json",
            "known_issue_review": root / "known-issue.json",
            "materiality_review": root / "materiality.json",
        }
        run_files = _run_evidence_files(self.project, run_id)
        file_metadata = {name: self._store_json_file(path) for name, path in files.items()}
        run_file_metadata = {name: self._store_json_file(path) for name, path in run_files.items()}
        expectations = {
            record["expectation_id"]: _without_record_hash(record)
            for record in self.project.records(run_id, "expectations")
        }
        observations = {
            record["observation_id"]: _without_record_hash(record)
            for record in self.project.records(run_id, "observations")
        }
        expectation_meta = [
            self.store.put_bytes(
                canonical_json(expectations[identifier]),
                media_type="application/json",
                original_name=f"{identifier}.expectation.json",
            )
            for identifier in candidate["expectation_ids"]
        ]
        observation_meta = [
            self.store.put_bytes(
                canonical_json(observations[identifier]),
                media_type="application/json",
                original_name=f"{identifier}.observation.json",
            )
            for identifier in candidate["observation_ids"]
        ]
        referenced_digests: set[str] = set()
        for path in (*files.values(), *run_files.values()):
            document = read_json(path)
            for reference in _cas_references(document):
                referenced_digests.add(reference["sha256"])
            if isinstance(document, dict):
                referenced_digests.update(document.get("evidence_hashes", []))
        referenced_metadata = [
            self.store.get_metadata(digest) for digest in sorted(referenced_digests)
        ]
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "candidate_id": candidate_id,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "ledger_last_hash": self.project.ledger(run_id).last_hash,
            "files": {name: metadata.to_reference() for name, metadata in file_metadata.items()},
            "run_files": {
                name: metadata.to_reference() for name, metadata in run_file_metadata.items()
            },
            "expectations": [metadata.to_reference() for metadata in expectation_meta],
            "observations": [metadata.to_reference() for metadata in observation_meta],
            "referenced_artifacts": [metadata.to_reference() for metadata in referenced_metadata],
        }
        manifest_bytes = canonical_json(manifest)
        if (
            _evidence_manifest_bytes is None
            or _expected_evidence_bundle_hash is None
            or manifest_bytes != _evidence_manifest_bytes
            or sha256_bytes(manifest_bytes) != _expected_evidence_bundle_hash
        ):
            raise ConcurrentModificationError(
                "The signed evidence manifest no longer matches the authorization graph.",
                details={
                    "prepared_sha256": _expected_evidence_bundle_hash,
                    "current_sha256": sha256_bytes(manifest_bytes),
                },
            )
        manifest_meta = self.store.put_bytes(
            _evidence_manifest_bytes,
            media_type="application/json",
            original_name=f"{candidate_id}.evidence-manifest.json",
        )
        issued_at = utc_now()
        experiment = read_json(files["experiment_result"])
        materiality = read_json(files["materiality_review"])
        verdict = {
            "schema_version": SCHEMA_VERSION,
            "verdict_id": f"V-{candidate_id[2:]}",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "issued_at": issued_at,
            "status": "VERIFIED",
            "authority_actor": authority.to_dict(),
            "policy_hash": run["protocol"]["sha256"],
            "reasons": list(report.reasons),
            "checks": report.checks,
            "proposer_actor_id": proposer_id,
            "executor_actor_id": experiment["executor"]["actor_id"],
            "separation_attestation": True,
            "evidence_bundle_hash": manifest_meta.sha256,
            "replay_result_hash": file_metadata["replay_result"].sha256,
            "counterevidence_review_hash": file_metadata["counterevidence_review"].sha256,
            "novelty_review_hash": file_metadata["novelty_review"].sha256,
            "materiality_review_hash": file_metadata["materiality_review"].sha256,
        }
        validate_or_raise("verdict", verdict)
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "verdict.json",
            verdict,
            actor=authority,
            event_type="VERDICT_AUTHORIZED",
            schema_name="verdict",
        )
        verdict_meta = self._store_json_file(root / "verdict.json")
        evidence_hashes = sorted(
            {
                manifest_meta.sha256,
                verdict_meta.sha256,
                *(metadata.sha256 for metadata in file_metadata.values()),
                *(metadata.sha256 for metadata in run_file_metadata.values()),
                *(metadata.sha256 for metadata in expectation_meta),
                *(metadata.sha256 for metadata in observation_meta),
                *(metadata.sha256 for metadata in referenced_metadata),
            }
        )
        expectations_text = [
            expectations[item]["statement"] for item in candidate["expectation_ids"]
        ]
        certificate = {
            "schema_version": SCHEMA_VERSION,
            "certificate_id": f"CERT-{candidate_id[2:]}",
            "run_id": run_id,
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis["hypothesis_id"],
            "issued_at": issued_at,
            "status": "VERIFIED",
            "belief_update": {
                "before": " | ".join(expectations_text),
                "after": candidate["discrepancy"],
            },
            "expectation_refs": [
                metadata.to_reference(schema_name="expectation") for metadata in expectation_meta
            ],
            "observation_refs": [
                metadata.to_reference(schema_name="observation") for metadata in observation_meta
            ],
            "main_hypothesis": hypothesis["main_hypothesis"],
            "alternative_explanations": hypothesis["benign_alternatives"],
            "falsification_conditions": hypothesis["falsification_conditions"],
            "experiment_plan_ref": file_metadata["experiment_plan"].to_reference(
                schema_name="experiment-plan"
            ),
            "experiment_result_ref": file_metadata["experiment_result"].to_reference(
                schema_name="experiment-result"
            ),
            "counterevidence_review_ref": file_metadata["counterevidence_review"].to_reference(
                schema_name="review"
            ),
            "replay_result_ref": file_metadata["replay_result"].to_reference(
                schema_name="replay-result"
            ),
            "novelty_review_ref": file_metadata["novelty_review"].to_reference(
                schema_name="review"
            ),
            "materiality_review_ref": file_metadata["materiality_review"].to_reference(
                schema_name="review"
            ),
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "decision_impact": materiality["decision_impact"],
            "limitations": [
                "Novelty is relative to the declared knowledge boundary.",
                "Actor identity and benchmark custody authenticity are external trust assumptions.",
            ],
            "unconfirmed": ["Global novelty is not claimed."],
            "verdict_ref": verdict_meta.to_reference(schema_name="verdict"),
            "authorization": {
                "authority_actor": authority.to_dict(),
                "policy_hash": run["protocol"]["sha256"],
                "authorized_at": issued_at,
            },
            "evidence_hashes": evidence_hashes,
            "evidence_bundle_hash": manifest_meta.sha256,
            "snapshot_binding": {
                "repository_commit": target["commit"],
                "target_snapshot_hash": target["snapshot_hash"],
                "protocol_hash": run["protocol"]["sha256"],
                "policy_hash": run["protocol"]["sha256"],
                "knowledge_boundary_hash": run["knowledge_boundary_hash"],
                "context_manifest_hash": run["context_manifest_hash"],
                "tool_versions": run["tools"],
            },
        }
        validate_or_raise("discovery-certificate", certificate)
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "certificate.yaml",
            certificate,
            actor=authority,
            event_type="CERTIFICATE_ISSUED",
            schema_name="discovery-certificate",
        )
        self.project.authorize_verified(
            run_id,
            candidate_id,
            actor=authority,
            reason="All frozen protocol gates passed; certificate and verdict were written first.",
        )
        return {"gate_report": report.to_dict(), "verdict": verdict, "certificate": certificate}

    def _audit_certificate(
        self,
        run_id: str,
        candidate_id: str,
        *,
        _authenticated_custody: bool = False,
        _authenticated_isolation: bool = False,
    ) -> dict[str, Any]:
        """Re-evaluate a VERIFIED certificate against its live evidence graph.

        A schema-valid certificate is not sufficient for publication.  This audit
        binds it back to the immutable CAS objects, current run snapshot, authority
        verdict, append-only state history, and the exact adjacent ledger events
        that issued the verdict, certificate, and VERIFIED transition.
        """

        root = self.project.candidate_dir(run_id, candidate_id)
        verdict_path = root / "verdict.json"
        certificate_path = root / "certificate.yaml"
        verdict = read_json(verdict_path)
        certificate = read_json(certificate_path)
        validate_or_raise("verdict", verdict)
        validate_or_raise("discovery-certificate", certificate)

        authority_data = verdict["authority_actor"]
        authority = Actor(authority_data["actor_id"], authority_data["role"])
        gate_report = self.evaluate(
            run_id,
            candidate_id,
            authority=authority,
            _authenticated_custody=_authenticated_custody,
            _authenticated_isolation=_authenticated_isolation,
        )
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        bundle = self.project.read_candidate(run_id, candidate_id)
        candidate = bundle["candidate"]
        hypothesis = bundle["hypothesis"]

        verdict_sha256 = sha256_file(verdict_path)
        certificate_sha256 = sha256_file(certificate_path)
        ledger = self.project.ledger(run_id)
        ledger_report = ledger.verify()
        events = ledger.read_all() if ledger_report.valid else []

        def matching_events(
            event_type: str,
            *,
            path: str | None = None,
            digest: str | None = None,
            to_state: str | None = None,
        ) -> list[dict[str, Any]]:
            matches: list[dict[str, Any]] = []
            for event in events:
                payload = event.get("payload", {})
                if event.get("event_type") != event_type:
                    continue
                if payload.get("candidate_id") != candidate_id:
                    continue
                if path is not None and payload.get("path") != path:
                    continue
                if digest is not None and payload.get("sha256") != digest:
                    continue
                if to_state is not None and payload.get("to_state") != to_state:
                    continue
                matches.append(event)
            return matches

        verdict_events = matching_events(
            "VERDICT_AUTHORIZED", path="verdict.json", digest=verdict_sha256
        )
        certificate_events = matching_events(
            "CERTIFICATE_ISSUED",
            path="certificate.yaml",
            digest=certificate_sha256,
        )
        verified_events = matching_events("STATE_TRANSITION", to_state="VERIFIED")

        marker_path = root / "authorization-commit.json"
        authorization_v2_marker_bound = False
        if marker_path.is_file():
            try:
                marker = read_json(marker_path)
                validate_or_raise("authorization-commit", marker)
                marker_sha256 = sha256_file(marker_path)
                marker_events = matching_events(
                    "AUTHORIZATION_COMMITTED",
                    path="authorization-commit.json",
                    digest=marker_sha256,
                )
                if (
                    len(marker_events) == 1
                    and len(verdict_events) == 1
                    and len(certificate_events) == 1
                    and len(verified_events) == 1
                ):
                    verdict_event = verdict_events[0]
                    certificate_event = certificate_events[0]
                    verified_event = verified_events[0]
                    marker_event = marker_events[0]
                    authorization_v2_marker_bound = all(
                        (
                            marker["run_id"] == run_id,
                            marker["candidate_id"] == candidate_id,
                            marker["prepared_graph_artifact_sha256"]
                            == marker["prepared_graph_sha256"],
                            self.store.verify(marker["prepared_graph_artifact_sha256"]).valid,
                            self.store.verify(marker["c_pre"]["sha256"]).valid,
                            marker["evidence_bundle_hash"] == certificate["evidence_bundle_hash"],
                            marker["evidence_bundle_hash"] == verdict["evidence_bundle_hash"],
                            marker["verdict_sha256"] == verdict_sha256,
                            marker["certificate_sha256"] == certificate_sha256,
                            marker["state_record_hash"]
                            == bundle["state_history"][-1]["record_hash"],
                            marker["c_pre"]["entries"] == verdict_event["sequence"],
                            marker["c_pre"]["last_hash"] == verdict_event["previous_event_hash"],
                            certificate_event["sequence"] == verdict_event["sequence"] + 1,
                            certificate_event["previous_event_hash"] == verdict_event["event_hash"],
                            verified_event["sequence"] == certificate_event["sequence"] + 1,
                            verified_event["previous_event_hash"]
                            == certificate_event["event_hash"],
                            marker_event["sequence"] == verified_event["sequence"] + 1,
                            marker_event["previous_event_hash"] == verified_event["event_hash"],
                            marker_event["sequence"] == marker["post_ledger_entries_before_marker"],
                            marker_event["previous_event_hash"]
                            == marker["post_ledger_head_before_marker"],
                            marker["post_ledger_entries_before_marker"]
                            == verified_event["sequence"] + 1,
                            marker["post_ledger_head_before_marker"]
                            == verified_event["event_hash"],
                        )
                    )
            except Exception:
                authorization_v2_marker_bound = False

        bundle_digest = certificate["evidence_bundle_hash"]
        bundle_verification = self.store.verify(bundle_digest)
        manifest: dict[str, Any] = {}
        if bundle_verification.valid:
            loaded_manifest = read_json(bundle_verification.path)
            if isinstance(loaded_manifest, dict):
                manifest = loaded_manifest

        manifest_files = manifest.get("files", {})
        manifest_run_files = manifest.get("run_files", {})
        current_files = {
            "candidate": root / "candidate.json",
            "hypothesis": root / "hypothesis.json",
            "experiment_plan": root / "experiment" / "plan.json",
            "experiment_result": root / "experiment" / "result.json",
            "experiment_environment": root / "experiment" / "environment.json",
            "counterevidence_review": root / "counterevidence" / "review.json",
            "replay_result": root / "replay" / "result.json",
            "replay_environment": root / "replay" / "environment.json",
            "novelty_review": root / "novelty.json",
            "known_issue_review": root / "known-issue.json",
            "materiality_review": root / "materiality.json",
        }
        current_file_bindings = isinstance(manifest_files, dict) and set(manifest_files) == set(
            current_files
        )
        if current_file_bindings:
            current_file_bindings = all(
                path.is_file()
                and isinstance(manifest_files[name], dict)
                and manifest_files[name].get("sha256") == sha256_file(path)
                for name, path in current_files.items()
            )
        current_run_files = _run_evidence_files(self.project, run_id)
        current_run_file_bindings = isinstance(manifest_run_files, dict) and set(
            manifest_run_files
        ) == set(current_run_files)
        if current_run_file_bindings:
            current_run_file_bindings = all(
                path.is_file()
                and isinstance(manifest_run_files[name], dict)
                and manifest_run_files[name].get("sha256") == sha256_file(path)
                for name, path in current_run_files.items()
            )

        expectation_digests = {
            hash_json(_without_record_hash(record))
            for record in self.project.records(run_id, "expectations")
            if record.get("expectation_id") in candidate["expectation_ids"]
        }
        observation_digests = {
            hash_json(_without_record_hash(record))
            for record in self.project.records(run_id, "observations")
            if record.get("observation_id") in candidate["observation_ids"]
        }
        manifest_expectation_digests = {
            reference.get("sha256") for reference in manifest.get("expectations", [])
        }
        manifest_observation_digests = {
            reference.get("sha256") for reference in manifest.get("observations", [])
        }
        certificate_expectation_digests = {
            reference.get("sha256") for reference in certificate["expectation_refs"]
        }
        certificate_observation_digests = {
            reference.get("sha256") for reference in certificate["observation_refs"]
        }

        manifest_artifact_digests = {
            reference.get("sha256")
            for reference in [
                *manifest_files.values(),
                *manifest_run_files.values(),
                *manifest.get("expectations", []),
                *manifest.get("observations", []),
                *manifest.get("referenced_artifacts", []),
            ]
            if isinstance(reference, dict)
        }
        certified_digests = set(certificate["evidence_hashes"])
        expected_certified_digests = manifest_artifact_digests | {
            bundle_digest,
            verdict_sha256,
        }
        all_cas_digests = certified_digests | {
            bundle_digest,
            certificate["verdict_ref"]["sha256"],
        }
        cas_objects_valid = all(self.store.verify(digest).valid for digest in all_cas_digests)

        blindness = read_json(current_run_files["blindness_attestation"])
        run_created_events = [event for event in events if event.get("event_type") == "RUN_CREATED"]
        run_event_bound = False
        if len(run_created_events) == 1:
            run_event_bound = all(
                (
                    run_created_events[0].get("sequence") == 0,
                    run_created_events[0].get("actor") == blindness.get("attested_by"),
                    run_created_events[0].get("payload")
                    == _expected_run_created_payload(run, target),
                )
            )

        artifact_event_types = {
            "experiment_plan": {"EXPERIMENT_PLANNED"},
            "experiment_environment": {"EXECUTION_ENVIRONMENT_RECORDED"},
            "experiment_result": {"EXPERIMENT_EXECUTED"},
            "counterevidence_review": {"COUNTEREVIDENCE_REVIEW_RECORDED"},
            "replay_result": {"REPLAY_COMPLETED", "EXTERNAL_REPLAY_IMPORTED"},
            "replay_environment": {
                "REPLAY_ENVIRONMENT_RECORDED",
                "EXTERNAL_REPLAY_ENVIRONMENT_IMPORTED",
            },
            "novelty_review": {"NOVELTY_REVIEW_RECORDED"},
            "known_issue_review": {"KNOWN_ISSUE_REVIEW_RECORDED"},
            "materiality_review": {"MATERIALITY_REVIEW_RECORDED"},
        }
        artifact_paths = {
            "experiment_plan": "experiment/plan.json",
            "experiment_environment": "experiment/environment.json",
            "experiment_result": "experiment/result.json",
            "counterevidence_review": "counterevidence/review.json",
            "replay_result": "replay/result.json",
            "replay_environment": "replay/environment.json",
            "novelty_review": "novelty.json",
            "known_issue_review": "known-issue.json",
            "materiality_review": "materiality.json",
        }
        artifact_documents = {name: read_json(current_files[name]) for name in artifact_event_types}
        artifact_actors = {
            "experiment_plan": artifact_documents["experiment_plan"]["planner"],
            "experiment_environment": artifact_documents["experiment_result"]["executor"],
            "experiment_result": artifact_documents["experiment_result"]["executor"],
            "counterevidence_review": artifact_documents["counterevidence_review"]["reviewer"],
            "replay_result": artifact_documents["replay_result"]["reproducer"],
            "replay_environment": artifact_documents["replay_result"]["reproducer"],
            "novelty_review": artifact_documents["novelty_review"]["reviewer"],
            "known_issue_review": artifact_documents["known_issue_review"]["reviewer"],
            "materiality_review": artifact_documents["materiality_review"]["reviewer"],
        }
        artifact_events_bound = True
        for name, event_types in artifact_event_types.items():
            expected_digest = manifest_files[name]["sha256"]
            matches = [
                event
                for event in events
                if event.get("event_type") in event_types
                and event.get("actor") == artifact_actors[name]
                and event.get("payload")
                == {
                    "candidate_id": candidate_id,
                    "path": artifact_paths[name],
                    "sha256": expected_digest,
                }
            ]
            if len(matches) != 1:
                artifact_events_bound = False

        knowledge_scan_event_bound = (
            len(
                [
                    event
                    for event in events
                    if event.get("event_type") == "KNOWLEDGE_SCAN_COMPLETED"
                    and event.get("payload")
                    == {
                        "path": "knowledge-scan.json",
                        "sha256": manifest_run_files["knowledge_scan"]["sha256"],
                    }
                ]
            )
            == 1
        )
        custody_event_bound = (
            len(
                [
                    event
                    for event in events
                    if event.get("event_type") == "BENCHMARK_CUSTODY_ATTESTED"
                    and event.get("payload")
                    == {
                        "path": "custody-attestation.json",
                        "sha256": manifest_run_files["custody_attestation"]["sha256"],
                    }
                ]
            )
            == 1
        )

        selected_expectations = [
            record
            for record in self.project.records(run_id, "expectations")
            if record.get("expectation_id") in candidate["expectation_ids"]
        ]
        selected_observations = [
            record
            for record in self.project.records(run_id, "observations")
            if record.get("observation_id") in candidate["observation_ids"]
        ]
        source_record_events_bound = all(
            len(
                [
                    event
                    for event in events
                    if event.get("event_type") == event_type
                    and event.get("payload")
                    == {
                        "collection": collection,
                        "record_id": record[identifier],
                        "record_hash": record["record_hash"],
                    }
                ]
            )
            == 1
            for records, event_type, collection, identifier in (
                (
                    selected_expectations,
                    "EXPECTATION_RECORDED",
                    "expectations",
                    "expectation_id",
                ),
                (
                    selected_observations,
                    "OBSERVATION_RECORDED",
                    "observations",
                    "observation_id",
                ),
            )
            for record in records
        )

        event_chain_bound = False
        event_actors_bound = False
        state_record_bound = False
        if len(verdict_events) == len(certificate_events) == len(verified_events) == 1:
            verdict_event = verdict_events[0]
            certificate_event = certificate_events[0]
            verified_event = verified_events[0]
            event_chain_bound = all(
                (
                    verdict_event["previous_event_hash"] == manifest.get("ledger_last_hash"),
                    certificate_event["previous_event_hash"] == verdict_event["event_hash"],
                    verified_event["previous_event_hash"] == certificate_event["event_hash"],
                    verdict_event["sequence"]
                    < certificate_event["sequence"]
                    < verified_event["sequence"],
                )
            )
            event_actors_bound = all(
                event.get("actor") == authority.to_dict()
                for event in (verdict_event, certificate_event, verified_event)
            )
            last_state = bundle["state_history"][-1]
            state_record_bound = all(
                (
                    last_state.get("from") == "REPRODUCED",
                    last_state.get("to") == "VERIFIED",
                    last_state.get("actor") == authority.to_dict(),
                    last_state.get("evidence_sha256") == certificate_sha256,
                    verified_event["payload"].get("from_state") == "REPRODUCED",
                    verified_event["payload"].get("evidence_sha256") == certificate_sha256,
                    verified_event["payload"].get("state_record_hash")
                    == last_state.get("record_hash"),
                )
            )

        reference_map = {
            "experiment_plan_ref": "experiment_plan",
            "experiment_result_ref": "experiment_result",
            "counterevidence_review_ref": "counterevidence_review",
            "replay_result_ref": "replay_result",
            "novelty_review_ref": "novelty_review",
            "materiality_review_ref": "materiality_review",
        }
        certificate_file_refs_bound = all(
            isinstance(manifest_files.get(manifest_name), dict)
            and certificate[certificate_name]["sha256"]
            == manifest_files[manifest_name].get("sha256")
            for certificate_name, manifest_name in reference_map.items()
        )

        experiment = read_json(current_files["experiment_result"])
        trial_policy_bound = True
        if run.get("trial_binding") is not None:
            preregistration, budget = self.project.validate_trial_binding(run_id) or ({}, None)
            trial_policy_bound = all(
                (
                    preregistration.get("protocol_hash") == run["protocol"]["sha256"],
                    preregistration.get("target_commit") == target["commit"],
                    budget is not None and budget.sha256 == run.get("budget_policy_hash"),
                )
            )
        checks = {
            "schemas_valid": True,
            "gate_re_evaluation_passed": gate_report.eligible,
            "ledger_valid": ledger_report.valid,
            "run_event_bound": run_event_bound,
            "artifact_events_bound": artifact_events_bound,
            "run_evidence_events_bound": knowledge_scan_event_bound and custody_event_bound,
            "source_record_events_bound": source_record_events_bound,
            "current_state_verified": bundle["state"] == "VERIFIED",
            "identity_bound": all(
                (
                    verdict["run_id"] == certificate["run_id"] == run_id,
                    verdict["candidate_id"] == certificate["candidate_id"] == candidate_id,
                    verdict["status"] == certificate["status"] == "VERIFIED",
                    verdict["issued_at"]
                    == certificate["issued_at"]
                    == certificate["authorization"]["authorized_at"],
                    certificate["hypothesis_id"] == hypothesis["hypothesis_id"],
                )
            ),
            "authority_bound": all(
                (
                    certificate["authorization"]["authority_actor"] == authority.to_dict(),
                    verdict["proposer_actor_id"] == candidate["proposed_by"]["actor_id"],
                    verdict["executor_actor_id"] == experiment["executor"]["actor_id"],
                    verdict["checks"] == gate_report.checks,
                )
            ),
            "snapshot_and_policy_bound": all(
                (
                    manifest.get("run_id") == run_id,
                    manifest.get("candidate_id") == candidate_id,
                    manifest.get("target_snapshot_hash") == target["snapshot_hash"],
                    manifest.get("protocol_hash") == run["protocol"]["sha256"],
                    verdict["policy_hash"] == run["protocol"]["sha256"],
                    certificate["authorization"]["policy_hash"] == run["protocol"]["sha256"],
                    certificate["knowledge_boundary_hash"] == run["knowledge_boundary_hash"],
                    certificate["snapshot_binding"]["repository_commit"] == target["commit"],
                    certificate["snapshot_binding"]["target_snapshot_hash"]
                    == target["snapshot_hash"],
                    certificate["snapshot_binding"]["protocol_hash"] == run["protocol"]["sha256"],
                    certificate["snapshot_binding"]["policy_hash"] == run["protocol"]["sha256"],
                    certificate["snapshot_binding"].get("knowledge_boundary_hash")
                    == run["knowledge_boundary_hash"],
                    certificate["snapshot_binding"].get("context_manifest_hash")
                    == run["context_manifest_hash"],
                    certificate["snapshot_binding"]["tool_versions"] == run["tools"],
                    trial_policy_bound,
                )
            ),
            "manifest_current_files_bound": current_file_bindings,
            "manifest_run_files_bound": current_run_file_bindings,
            "expectations_bound": expectation_digests
            == manifest_expectation_digests
            == certificate_expectation_digests,
            "observations_bound": observation_digests
            == manifest_observation_digests
            == certificate_observation_digests,
            "certificate_file_refs_bound": certificate_file_refs_bound,
            "evidence_set_complete": certified_digests == expected_certified_digests,
            "cas_objects_valid": cas_objects_valid,
            "bundle_hash_bound": all(
                (
                    bundle_verification.valid,
                    verdict["evidence_bundle_hash"] == bundle_digest,
                    certificate["verdict_ref"]["sha256"] == verdict_sha256,
                )
            ),
            "verdict_evidence_bound": all(
                (
                    verdict["replay_result_hash"]
                    == manifest_files.get("replay_result", {}).get("sha256"),
                    verdict["counterevidence_review_hash"]
                    == manifest_files.get("counterevidence_review", {}).get("sha256"),
                    verdict["novelty_review_hash"]
                    == manifest_files.get("novelty_review", {}).get("sha256"),
                    verdict["materiality_review_hash"]
                    == manifest_files.get("materiality_review", {}).get("sha256"),
                )
            ),
            "issuance_events_bound": event_chain_bound,
            "issuance_actors_bound": event_actors_bound,
            "verified_state_record_bound": state_record_bound,
            "authorization_v2_marker_bound": authorization_v2_marker_bound,
        }
        failed_checks = sorted(name for name, passed in checks.items() if not passed)
        return {
            "valid": not failed_checks,
            "checks": checks,
            "failed_checks": failed_checks,
            "gate_report": gate_report.to_dict(),
            "certificate_sha256": certificate_sha256,
            "verdict_sha256": verdict_sha256,
        }

    def audit_certificate(self, run_id: str, candidate_id: str) -> dict[str, Any]:
        """Audit legacy/local evidence without accepting caller-declared authentication."""

        try:
            return self._audit_certificate(run_id, candidate_id)
        except Exception as exc:
            # Public audit is a total fail-closed inspection boundary. Malformed or
            # concurrently corrupted producer evidence is an invalid certificate,
            # never an unhandled parser/shape exception that can abort a report run.
            return {
                "valid": False,
                "checks": {"audit_completed": False},
                "failed_checks": ["audit_completed"],
                "certificate_sha256": None,
                "verdict_sha256": None,
                "error": {
                    "code": getattr(exc, "code", "INTEGRITY_ERROR"),
                    "message": "Certificate evidence could not be audited safely.",
                    "details": {"exception_type": type(exc).__name__},
                },
            }

    @_consistent_authority_read
    def audit_certificate_v2(
        self,
        run_id: str,
        candidate_id: str,
        *,
        authority: Actor,
        authority_envelope_bytes: bytes,
        checkpoint_envelope_bytes: bytes,
        custody_envelope_bytes: bytes,
        isolation_envelope_bytes: bytes,
        trust_policy_bytes: bytes,
        trust_policy_sha256: str,
        manifest_bytes: bytes,
        isolation_result_bytes: bytes,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Re-authenticate every v2 external input and require the atomic commit marker."""

        root = self.project.candidate_dir(run_id, candidate_id)
        marker_bytes, _ = self._stable_evidence_read(
            root / "authorization-commit.json", "authorization_commit"
        )
        marker = parse_strict_json(marker_bytes)
        validate_or_raise("authorization-commit", marker)
        verdict_bytes, _ = self._stable_evidence_read(root / "verdict.json", "verdict")
        verdict = parse_strict_json(verdict_bytes)
        validate_or_raise("verdict", verdict)
        if verdict["authority_actor"] != authority.to_dict():
            raise IntegrityError("Authority audit actor does not match the committed verdict.")
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        binding = run.get("trial_binding")
        if not isinstance(binding, dict):
            raise IntegrityError("Authority v2 certificate lacks a trial binding.")
        policy = load_trust_policy(trust_policy_bytes, expected_sha256=trust_policy_sha256, now=now)
        if policy.mode != "PRODUCTION":
            raise PolicyError("Authority v2 audit requires a PRODUCTION trust policy.")
        if sha256_bytes(manifest_bytes) != binding["manifest_hash"]:
            raise IntegrityError("Custody manifest bytes do not match the trial binding.")
        replay_bytes, _ = self._stable_evidence_read(
            root / "replay" / "result.json", "replay_result_subject"
        )
        if replay_bytes != isolation_result_bytes:
            raise IntegrityError("Isolation subject is not the current replay result bytes.")
        custody = verify_custody_attestation(
            custody_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            manifest_bytes=manifest_bytes,
            expected_suite_id=binding["suite_id"],
            expected_manifest_sha256=binding["manifest_hash"],
            now=now,
        )
        isolation = verify_isolation_attestation(
            isolation_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            result_bytes=isolation_result_bytes,
            expected_suite_id=binding["suite_id"],
            expected_case_id=binding["case_id"],
            expected_variant=binding["variant"],
            expected_run_id=run_id,
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=run["protocol"]["sha256"],
            now=now,
        )
        self.store.verify_or_raise(marker["c_pre"]["sha256"])
        c_pre_bytes = self.store.read_bytes(marker["c_pre"]["sha256"])
        checkpoint = verify_ledger_checkpoint(
            checkpoint_envelope_bytes,
            trust_policy_bytes=trust_policy_bytes,
            trust_policy_sha256=trust_policy_sha256,
            ledger_bytes=c_pre_bytes,
            expected_suite_id=binding["suite_id"],
            expected_case_id=binding["case_id"],
            expected_variant=binding["variant"],
            expected_run_id=run_id,
            expected_target_snapshot_hash=target["snapshot_hash"],
            expected_protocol_hash=run["protocol"]["sha256"],
            now=now,
        )
        self.store.verify_or_raise(marker["prepared_graph_artifact_sha256"])
        graph_bytes = self.store.read_bytes(marker["prepared_graph_artifact_sha256"])
        for field_name, envelope_bytes in (
            ("authority_envelope_sha256", authority_envelope_bytes),
            ("checkpoint_envelope_sha256", checkpoint_envelope_bytes),
            ("custody_envelope_sha256", custody_envelope_bytes),
            ("isolation_envelope_sha256", isolation_envelope_bytes),
        ):
            digest = marker[field_name]
            self.store.verify_or_raise(digest)
            if self.store.read_bytes(digest) != envelope_bytes:
                raise IntegrityError(
                    "Retained external attestation does not match the audited envelope.",
                    details={"field": field_name},
                )
        authority_type = "https://schemas.unasked.dev/attestations/authority-authorization/v0.4"
        signed_authority = verify_dsse_statement(
            authority_envelope_bytes,
            expected_predicate_type=authority_type,
            trusted_keys=policy.keys_for(authority_type),
            threshold=policy.threshold_for(authority_type),
            predicate_schema="authority-authorization-predicate",
        )
        _require_subject_sha256(signed_authority.statement, graph_bytes)
        if not all(
            item.production_qualified for item in (custody, isolation, checkpoint, signed_authority)
        ):
            raise PolicyError("Authority v2 audit inputs are not production-qualified.")
        graph = parse_strict_json(graph_bytes)
        expected_graph = {
            "schema_version": "0.4.0",
            "run_id": run_id,
            "candidate_id": candidate_id,
            "source_state": "REPRODUCED",
            "target_state": "VERIFIED",
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "context_manifest_hash": run["context_manifest_hash"],
            "ledger": marker["c_pre"],
            "external_attestations": {
                "trust_policy_sha256": trust_policy_sha256,
                "checkpoint_envelope_sha256": sha256_bytes(checkpoint_envelope_bytes),
                "custody_envelope_sha256": sha256_bytes(custody_envelope_bytes),
                "isolation_envelope_sha256": sha256_bytes(isolation_envelope_bytes),
            },
        }
        if set(graph) != {*expected_graph, "files"} or any(
            graph.get(field_name) != value for field_name, value in expected_graph.items()
        ):
            raise IntegrityError("Stored authorization graph does not match committed inputs.")
        if not isinstance(graph.get("files"), list):
            raise IntegrityError("Stored authorization graph has an invalid file manifest.")
        for descriptor in graph["files"]:
            if (
                not isinstance(descriptor, dict)
                or set(descriptor) != {"path", "sha256", "artifact_sha256", "size"}
                or descriptor["sha256"] != descriptor["artifact_sha256"]
            ):
                raise IntegrityError("Stored authorization graph has an invalid preimage binding.")
            verification = self.store.verify_or_raise(descriptor["artifact_sha256"])
            if verification.size != descriptor["size"]:
                raise IntegrityError("Stored authorization graph preimage size does not match.")
        graph_sha256 = sha256_bytes(graph_bytes)
        self.store.verify_or_raise(marker["evidence_bundle_hash"])
        evidence_manifest_bytes = self.store.read_bytes(marker["evidence_bundle_hash"])
        if sha256_bytes(evidence_manifest_bytes) != marker["evidence_bundle_hash"]:
            raise IntegrityError("Stored evidence manifest digest does not match the marker.")
        expected_marker = {
            "prepared_graph_sha256": graph_sha256,
            "prepared_graph_artifact_sha256": graph_sha256,
            "evidence_bundle_hash": sha256_bytes(evidence_manifest_bytes),
            "trust_policy_sha256": trust_policy_sha256,
            "checkpoint_envelope_sha256": sha256_bytes(checkpoint_envelope_bytes),
            "checkpoint_payload_sha256": checkpoint.payload_sha256,
            "custody_envelope_sha256": sha256_bytes(custody_envelope_bytes),
            "custody_payload_sha256": custody.payload_sha256,
            "isolation_envelope_sha256": sha256_bytes(isolation_envelope_bytes),
            "isolation_payload_sha256": isolation.payload_sha256,
            "authority_envelope_sha256": sha256_bytes(authority_envelope_bytes),
            "authority_payload_sha256": signed_authority.payload_sha256,
        }
        for field_name, value in expected_marker.items():
            if marker[field_name] != value:
                raise IntegrityError(
                    "Authorization marker does not match re-authenticated v2 inputs.",
                    details={"field": field_name},
                )
        predicate = signed_authority.predicate
        expected_predicate = {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "target_snapshot_hash": target["snapshot_hash"],
            "protocol_hash": run["protocol"]["sha256"],
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "context_manifest_hash": run["context_manifest_hash"],
            "evidence_bundle_hash": marker["evidence_bundle_hash"],
            "ledger_checkpoint_envelope_sha256": marker["checkpoint_envelope_sha256"],
            "custody_envelope_sha256": marker["custody_envelope_sha256"],
            "isolation_envelope_sha256": marker["isolation_envelope_sha256"],
            "prepared_graph_sha256": marker["prepared_graph_sha256"],
            "decision": "AUTHORIZE_VERIFIED",
            "authorized_state": "VERIFIED",
            "trust_policy_sha256": trust_policy_sha256,
            "issuer_actor_id": authority.actor_id,
        }
        for field_name, value in expected_predicate.items():
            if predicate[field_name] != value:
                raise IntegrityError(
                    "Signed authority predicate does not match the committed authorization.",
                    details={"field": field_name},
                )
        if _parse_time(predicate["expires_at"], "expires_at") < _selected_time(now):
            raise PolicyError("Signed authority authorization is expired.")
        self._require_production_actor_separation(
            run_id,
            candidate_id,
            authority=authority,
            custody=custody,
            isolation=isolation,
            checkpoint=checkpoint,
            signed_authority=signed_authority,
        )
        audit = self._audit_certificate(
            run_id,
            candidate_id,
            _authenticated_custody=True,
            _authenticated_isolation=True,
        )
        if not audit["valid"]:
            raise IntegrityError("Authority v2 certificate audit failed.", details=audit)
        return audit
