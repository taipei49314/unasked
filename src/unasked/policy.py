from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from unasked.errors import PolicyError


class State(StrEnum):
    SIGNAL = "SIGNAL"
    CANDIDATE = "CANDIDATE"
    HYPOTHESIZED = "HYPOTHESIZED"
    TESTABLE = "TESTABLE"
    SUPPORTED = "SUPPORTED"
    REPRODUCED = "REPRODUCED"
    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    DUPLICATE = "DUPLICATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NON_MATERIAL = "NON_MATERIAL"
    ENVIRONMENTAL = "ENVIRONMENTAL"
    STALE = "STALE"
    REVOKED = "REVOKED"


class Capability(StrEnum):
    OBSERVE = "OBSERVE"
    PROPOSE_CANDIDATE = "PROPOSE_CANDIDATE"
    REQUEST_EXPERIMENT = "REQUEST_EXPERIMENT"
    EXECUTE_SANDBOX = "EXECUTE_SANDBOX"
    SUBMIT_EVIDENCE = "SUBMIT_EVIDENCE"
    CHALLENGE = "CHALLENGE"
    REPLAY = "REPLAY"
    AUTHORIZE_VERDICT = "AUTHORIZE_VERDICT"
    PUBLISH = "PUBLISH"


ROLE_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "principal_investigator": frozenset({Capability.PUBLISH}),
    "explorer": frozenset(
        {
            Capability.OBSERVE,
            Capability.PROPOSE_CANDIDATE,
            Capability.REQUEST_EXPERIMENT,
            Capability.SUBMIT_EVIDENCE,
        }
    ),
    "experiment_planner": frozenset({Capability.OBSERVE, Capability.REQUEST_EXPERIMENT}),
    "sandbox_executor": frozenset({Capability.EXECUTE_SANDBOX, Capability.SUBMIT_EVIDENCE}),
    "falsifier": frozenset({Capability.OBSERVE, Capability.CHALLENGE, Capability.SUBMIT_EVIDENCE}),
    "independent_reproducer": frozenset({Capability.REPLAY, Capability.SUBMIT_EVIDENCE}),
    "authority_kernel": frozenset({Capability.AUTHORIZE_VERDICT}),
    "human_judge": frozenset({Capability.AUTHORIZE_VERDICT, Capability.PUBLISH}),
    "system": frozenset(),
}

SCHEMA_ROLE_NAMES = {
    "principal_investigator": "PRINCIPAL_INVESTIGATOR",
    "explorer": "EXPLORER",
    "experiment_planner": "EXPERIMENT_PLANNER",
    "sandbox_executor": "SANDBOX_EXECUTOR",
    "falsifier": "FALSIFIER",
    "independent_reproducer": "INDEPENDENT_REPRODUCER",
    "authority_kernel": "DISCOVERY_AUTHORITY_KERNEL",
    "discovery_authority_kernel": "DISCOVERY_AUTHORITY_KERNEL",
    "human_judge": "HUMAN_JUDGE",
    "system": "SYSTEM",
}

REJECTION_STATES = frozenset(
    {
        State.FALSIFIED,
        State.DUPLICATE,
        State.INCONCLUSIVE,
        State.NON_MATERIAL,
        State.ENVIRONMENTAL,
        State.STALE,
    }
)

ALLOWED_TRANSITIONS: dict[State, frozenset[State]] = {
    State.SIGNAL: frozenset({State.CANDIDATE, *REJECTION_STATES}),
    State.CANDIDATE: frozenset({State.HYPOTHESIZED, *REJECTION_STATES}),
    State.HYPOTHESIZED: frozenset({State.TESTABLE, *REJECTION_STATES}),
    State.TESTABLE: frozenset({State.SUPPORTED, *REJECTION_STATES}),
    State.SUPPORTED: frozenset({State.REPRODUCED, *REJECTION_STATES}),
    State.REPRODUCED: frozenset({State.VERIFIED, *REJECTION_STATES}),
    State.VERIFIED: frozenset({State.REVOKED, State.STALE}),
    State.FALSIFIED: frozenset(),
    State.DUPLICATE: frozenset(),
    State.INCONCLUSIVE: frozenset(),
    State.NON_MATERIAL: frozenset(),
    State.ENVIRONMENTAL: frozenset(),
    State.STALE: frozenset(),
    State.REVOKED: frozenset(),
}

FORBIDDEN_P0_CLAIMS = (
    "autonomous discovery agent",
    "finds unknown bugs",
    "self-driving researcher",
    "validated proactive intelligence",
    "ai has learned proactive discovery",
)


@dataclass(frozen=True)
class Actor:
    actor_id: str
    role: str

    @property
    def capabilities(self) -> frozenset[Capability]:
        role = self.role.casefold()
        if role == "discovery_authority_kernel":
            role = "authority_kernel"
        try:
            return ROLE_CAPABILITIES[role]
        except KeyError as exc:
            raise PolicyError("Unknown authority role.", details={"role": self.role}) from exc

    def to_dict(self) -> dict[str, object]:
        role = self.role.casefold()
        try:
            schema_role = SCHEMA_ROLE_NAMES[role]
        except KeyError as exc:
            raise PolicyError("Unknown authority role.", details={"role": self.role}) from exc
        return {
            "actor_id": self.actor_id,
            "role": schema_role,
            "capabilities": sorted(capability.value for capability in self.capabilities),
        }


def require_capability(actor: Actor, capability: Capability) -> None:
    if capability not in actor.capabilities:
        raise PolicyError(
            "Actor lacks required capability.",
            details={
                "actor_id": actor.actor_id,
                "role": actor.role,
                "required": capability.value,
            },
        )


def require_distinct_actors(proposer_id: str, authority_id: str) -> None:
    if proposer_id == authority_id:
        raise PolicyError(
            "Proposal and verdict authority must be separate actors.",
            details={"actor_id": proposer_id},
        )


def require_transition(current: State | str, target: State | str) -> None:
    current_state = State(current)
    target_state = State(target)
    if target_state not in ALLOWED_TRANSITIONS[current_state]:
        raise PolicyError(
            "Illegal discovery lifecycle transition.",
            details={"from": current_state.value, "to": target_state.value},
        )


def assert_p0_claim_allowed(text: str) -> None:
    normalized = " ".join(text.casefold().split())
    matches = [claim for claim in FORBIDDEN_P0_CLAIMS if claim in normalized]
    if matches:
        raise PolicyError("Claim is not authorized at P0.", details={"forbidden_matches": matches})


def missing_requirements(checks: dict[str, bool], required: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(name for name in required if checks.get(name) is not True))
