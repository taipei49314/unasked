"""Benchmark-neutral deterministic signal baseline.

The baseline is intentionally read-only.  It inspects facts produced from the
immutable Git object named by a run and returns canonical-JSON-compatible records
for a caller to place in CAS and reference from the append-only ledger.  It does
not create candidates, write lifecycle state, or authorize claims.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from unasked.errors import IntegrityError
from unasked.observer import observe_repository
from unasked.project import SCHEMA_VERSION, Project
from unasked.protocol import load_protocol, protocol_hash
from unasked.schemas import validate_or_raise
from unasked.util import hash_json

BASELINE_NAME = "deterministic-control-signal-baseline"
BASELINE_VERSION = "0.1.0"
NORMALIZED_BUDGET_POLICY = "UNASKED-NORMALIZED-STATIC-SCAN-v1"

_SIGNAL_CATEGORIES = frozenset({"continue_on_error", "skip", "suppression"})


def _detector_metadata() -> dict[str, Any]:
    # Return a fresh value so a caller cannot mutate module state through the
    # result object and influence a later deterministic run.
    return {
        "name": BASELINE_NAME,
        "version": BASELINE_VERSION,
        "rules": sorted(_SIGNAL_CATEGORIES),
        "benchmark_specific_rules": False,
    }


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrityError("Baseline input must contain a JSON object.", details={"field": field})
    return value


def _bound_inputs(project: Project, run_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Load and recheck the immutable run, target, and protocol bindings."""

    run = project.get_run(run_id)
    validate_or_raise("run", run)
    target = project.get_target(run_id)

    if run.get("run_id") != run_id:
        raise IntegrityError(
            "Run identity does not match its storage location.",
            details={"expected": run_id, "actual": run.get("run_id")},
        )

    try:
        snapshot_identity = {
            "commit": target["commit"],
            "tree": target["tree"],
            "submodules": target.get("submodules", []),
            "dependency_locks": target.get("dependency_locks", []),
        }
        stored_identity = target["snapshot_identity"]
        snapshot_hash = target["snapshot_hash"]
        run_target = _require_mapping(run["target"], "run.target")
        run_protocol = _require_mapping(run["protocol"], "run.protocol")
    except KeyError as exc:
        raise IntegrityError(
            "Run target is missing an immutable binding.", details={"field": str(exc)}
        ) from exc

    if stored_identity != snapshot_identity:
        raise IntegrityError("Stored snapshot identity does not match target metadata.")
    actual_snapshot_hash = hash_json(snapshot_identity)
    if snapshot_hash != actual_snapshot_hash:
        raise IntegrityError(
            "Target snapshot hash does not match its immutable identity.",
            details={"expected": snapshot_hash, "actual": actual_snapshot_hash},
        )
    if (
        run_target.get("snapshot_hash") != snapshot_hash
        or run_target.get("repository_commit") != target["commit"]
    ):
        raise IntegrityError("Run and target snapshot bindings disagree.")

    frozen_protocol = load_protocol(project.paths(run_id).protocol)
    actual_protocol_hash = protocol_hash(frozen_protocol)
    if run_protocol.get("sha256") != actual_protocol_hash:
        raise IntegrityError(
            "Frozen protocol hash does not match the run binding.",
            details={
                "expected": run_protocol.get("sha256"),
                "actual": actual_protocol_hash,
            },
        )
    if run_protocol.get("version") != frozen_protocol.get("protocol_version"):
        raise IntegrityError("Frozen protocol version does not match the run binding.")

    return run, target, actual_protocol_hash


def _signal_category(observation: Mapping[str, Any]) -> str | None:
    fact = _require_mapping(observation.get("fact"), "observation.fact")
    category = fact.get("category")
    if observation.get("kind") == "control_signal" and category in _SIGNAL_CATEGORIES:
        return str(category)
    if fact.get("fact_type") == "continue_on_error":
        return "continue_on_error"
    return None


def _source_record(observation: Mapping[str, Any]) -> dict[str, Any]:
    source = _require_mapping(observation.get("source"), "observation.source")
    integrity = _require_mapping(observation.get("integrity"), "observation.integrity")
    required = ("path", "sha256", "line_start", "line_end")
    missing = [field for field in required if field not in source]
    if missing:
        raise IntegrityError(
            "Observation source is incomplete.", details={"missing": sorted(missing)}
        )
    return {
        "path": source["path"],
        "sha256": source["sha256"],
        "line_start": source["line_start"],
        "line_end": source["line_end"],
        "git_object": integrity.get("git_object"),
    }


def _signal_record(
    observation: Mapping[str, Any],
    *,
    category: str,
    run_id: str,
    snapshot_hash: str,
    snapshot_commit: str,
    protocol_digest: str,
) -> dict[str, Any]:
    fact = _require_mapping(observation.get("fact"), "observation.fact")
    source = _source_record(observation)
    evidence: dict[str, Any] = {}
    for field in ("matched_text", "line_text", "key", "value", "yaml_path"):
        if field in fact:
            evidence[field] = fact[field]

    identity = {
        "record_type": "DETERMINISTIC_SIGNAL",
        "run_id": run_id,
        "snapshot_hash": snapshot_hash,
        "snapshot_commit": snapshot_commit,
        "protocol_hash": protocol_digest,
        "detector": {"name": BASELINE_NAME, "version": BASELINE_VERSION},
        "rule_id": f"control-signal/{category}",
        "category": category,
        "source_observation_id": observation["observation_id"],
        "source": source,
        "evidence": evidence,
        "claim_scope": "NON_DISCOVERY_SIGNAL_ONLY",
        "lifecycle_effect": "NONE",
    }
    record = {
        "schema_version": SCHEMA_VERSION,
        "signal_id": f"SIG-{hash_json(identity)[:24]}",
        **identity,
    }
    record["record_hash"] = hash_json(record)
    return record


def _normalized_budget(observations: list[dict[str, Any]]) -> dict[str, Any]:
    structures = [item for item in observations if item.get("kind") == "repository_structure"]
    snapshot_bytes = 0
    for item in structures:
        fact = _require_mapping(item.get("fact"), "observation.fact")
        size = fact.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise IntegrityError("Repository structure observation has an invalid byte size.")
        snapshot_bytes += size

    snapshot_kib = (snapshot_bytes + 1023) // 1024
    entry_units = len(structures)
    classification_units = len(observations)
    consumed = entry_units + snapshot_kib + classification_units
    return {
        "policy_id": NORMALIZED_BUDGET_POLICY,
        "unit": "normalized_investigation_unit",
        "formula": ("snapshot_entries + ceil(snapshot_bytes / 1024) + observations_classified"),
        "usage": {
            "snapshot_passes": 1,
            "snapshot_entries": entry_units,
            "snapshot_bytes": snapshot_bytes,
            "snapshot_kib_units": snapshot_kib,
            "observations_classified": classification_units,
            "model_calls": 0,
            "network_requests": 0,
            "experiment_commands": 0,
        },
        "consumed_units": consumed,
        "workload_bound_units": consumed,
        "within_workload_bound": True,
    }


def run_deterministic_baseline(project: Project, run_id: str) -> dict[str, Any]:
    """Return deterministic signal records for an immutable UNASKED run.

    The return value is a pure JSON value.  A caller may serialize it with
    :func:`unasked.util.canonical_json`, store those exact bytes in
    :class:`unasked.artifacts.ArtifactStore`, and append the resulting artifact
    reference to a ``DETERMINISTIC_BASELINE_COMPLETED`` ledger event.  This
    function deliberately performs neither mutation.
    """

    run, target, protocol_digest = _bound_inputs(project, run_id)
    observations = observe_repository(target["repository_path"], target)

    for observation in observations:
        if observation.get("snapshot_commit") != target["commit"]:
            raise IntegrityError("Observation is not bound to the selected snapshot commit.")
        _source_record(observation)

    # CI parsers and the generic control scanner can describe the same
    # continue-on-error line.  Prefer the richer control-signal observation and
    # emit one stable signal per rule/source location.
    selected: dict[tuple[Any, ...], dict[str, Any]] = {}
    for observation in observations:
        category = _signal_category(observation)
        if category is None:
            continue
        source = _source_record(observation)
        key = (
            category,
            source["path"],
            source["sha256"],
            source["line_start"],
            source["line_end"],
        )
        previous = selected.get(key)
        if previous is None or (
            observation.get("kind") == "control_signal" and previous.get("kind") != "control_signal"
        ):
            selected[key] = observation

    signals = [
        _signal_record(
            selected[key],
            category=str(key[0]),
            run_id=run_id,
            snapshot_hash=target["snapshot_hash"],
            snapshot_commit=target["commit"],
            protocol_digest=protocol_digest,
        )
        for key in sorted(selected)
    ]
    observation_manifest = [
        {
            "observation_id": item["observation_id"],
            "kind": item["kind"],
            "source": _source_record(item),
            "fact_hash": hash_json(item["fact"]),
            "capture_method": item["capture_method"],
        }
        for item in observations
    ]
    baseline_identity = {
        "run_id": run_id,
        "snapshot_hash": target["snapshot_hash"],
        "protocol_hash": protocol_digest,
        "detector": _detector_metadata(),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "DETERMINISTIC_BASELINE_RESULT",
        "baseline_run_id": f"BASE-{hash_json(baseline_identity)[:24]}",
        "run_id": run_id,
        "snapshot_hash": target["snapshot_hash"],
        "snapshot_commit": target["commit"],
        "protocol_hash": protocol_digest,
        "protocol_version": run["protocol"]["version"],
        "detector": _detector_metadata(),
        "observation_manifest_hash": hash_json(observation_manifest),
        "claim_scope": "NON_DISCOVERY_SIGNAL_ONLY",
        "lifecycle_effect": "NONE",
        "signal_count": len(signals),
        "signals": signals,
        "normalized_budget": _normalized_budget(observations),
        "integration": {
            "canonical_encoding": "unasked.canonical_json",
            "media_type": "application/vnd.unasked.deterministic-baseline+json",
            "ledger_event_type": "DETERMINISTIC_BASELINE_COMPLETED",
        },
    }


__all__ = [
    "BASELINE_NAME",
    "BASELINE_VERSION",
    "NORMALIZED_BUDGET_POLICY",
    "run_deterministic_baseline",
]
