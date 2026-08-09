from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from unasked import CLAIM, PROTOCOL_VERSION
from unasked.errors import UsageError
from unasked.util import hash_json, read_json

AUTHORIZATION_GATES = (
    "unasked_attestation",
    "declared_knowledge_boundary",
    "expectation_evidence",
    "observation_evidence",
    "discrepancy_evidence",
    "falsifiable_hypothesis",
    "experiment_complete",
    "experiment_environment_bound",
    "counterevidence_complete",
    "clean_replay_passed",
    "replay_environment_bound",
    "replay_input_bound",
    "replay_outputs_bound",
    "external_isolation_attested",
    "novelty_review_approved",
    "materiality_review_approved",
    "artifact_integrity",
    "source_replay",
    "ledger_integrity",
    "legal_state_history",
    "protocol_frozen",
    "snapshot_bound",
    "identity_bound",
    "independent_authority",
)

DEFAULT_PROTOCOL: dict[str, Any] = {
    "protocol_id": "UNASKED-P0-0.1",
    "protocol_version": PROTOCOL_VERSION,
    "charter_source_sha256": ("3c5b6e607f460581c7a85ecdbb695a54681a8d34b5bc2418896c3ab9dd0b86a"),
    "claim": CLAIM,
    "high_level_prompt": (
        "Investigate this repository for material discrepancies. "
        "Do not assume that a discovery exists."
    ),
    "false_verified_claim_rate_target": 0,
    "artifact_hash": "sha256",
    "ledger_mode": "append-only-hash-chain",
    "verified_requires": list(AUTHORIZATION_GATES),
    "counterevidence_types": [
        "benign_alternative",
        "negative_control",
        "semantic_variant",
        "completeness_check",
    ],
    "scope_locks": {
        "web_ui": False,
        "automatic_repair": False,
        "continuous_notifications": False,
        "multi_agent_product_orchestration": False,
        "vector_database": False,
        "private_benchmark_in_repository": False,
    },
}


def load_protocol(path: Path | None = None) -> dict[str, Any]:
    protocol = deepcopy(DEFAULT_PROTOCOL) if path is None else read_json(path)
    required = {"protocol_id", "protocol_version", "verified_requires", "scope_locks"}
    missing = sorted(required - protocol.keys())
    if missing:
        raise UsageError("Protocol is missing required fields.", details={"missing": missing})
    if tuple(protocol["verified_requires"]) != AUTHORIZATION_GATES:
        raise UsageError(
            "Protocol verified_requires must exactly match the implemented P0 gates.",
            details={
                "expected": list(AUTHORIZATION_GATES),
                "actual": protocol["verified_requires"],
            },
        )
    return protocol


def protocol_hash(protocol: dict[str, Any]) -> str:
    return hash_json(protocol)
