from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from unasked.errors import UsageError
from unasked.util import hash_json

_LIMIT_FIELDS = (
    "max_turns",
    "max_provider_calls",
    "max_tool_calls",
    "max_candidates",
    "max_experiments",
    "max_experiment_commands",
    "max_wall_seconds",
    "max_request_bytes",
    "max_response_bytes",
    "max_total_request_bytes",
    "max_file_bytes",
    "max_search_matches",
    "max_inventory_entries",
    "max_observations",
)


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    """Finite limits frozen before the first Explorer provider call."""

    max_turns: int
    max_provider_calls: int
    max_tool_calls: int
    max_candidates: int
    max_experiments: int
    max_experiment_commands: int
    max_wall_seconds: int
    max_request_bytes: int
    max_response_bytes: int
    max_total_request_bytes: int
    max_file_bytes: int
    max_search_matches: int
    max_inventory_entries: int
    max_observations: int
    schema_version: str = "0.1.0"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BudgetPolicy:
        if not isinstance(value, dict):
            raise UsageError("Budget policy must be a JSON object.")
        allowed = {"schema_version", *_LIMIT_FIELDS}
        unknown = sorted(set(value) - allowed)
        missing = sorted(set(_LIMIT_FIELDS) - value.keys())
        if unknown or missing:
            raise UsageError(
                "Budget policy fields are not exact.",
                details={"missing": missing, "unknown": unknown},
            )
        if value.get("schema_version", "0.1.0") != "0.1.0":
            raise UsageError("Budget policy schema_version must be 0.1.0.")
        normalized: dict[str, int] = {}
        for name in _LIMIT_FIELDS:
            raw = value[name]
            if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
                raise UsageError(
                    "Budget limits must be finite non-negative integers.",
                    details={"field": name, "value": raw},
                )
            normalized[name] = raw
        for required_positive in (
            "max_turns",
            "max_provider_calls",
            "max_wall_seconds",
            "max_request_bytes",
            "max_response_bytes",
            "max_total_request_bytes",
        ):
            if normalized[required_positive] == 0:
                raise UsageError(
                    "Core investigation budget limits must be positive.",
                    details={"field": required_positive},
                )
        return cls(**normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            **{name: getattr(self, name) for name in _LIMIT_FIELDS},
        }

    @property
    def sha256(self) -> str:
        return hash_json(self.to_dict())


DEFAULT_M0_BUDGET = BudgetPolicy(
    max_turns=12,
    max_provider_calls=12,
    max_tool_calls=8,
    max_candidates=2,
    max_experiments=2,
    max_experiment_commands=4,
    max_wall_seconds=300,
    max_request_bytes=262_144,
    max_response_bytes=65_536,
    max_total_request_bytes=1_048_576,
    max_file_bytes=65_536,
    max_search_matches=64,
    max_inventory_entries=500,
    max_observations=500,
)


@dataclass(slots=True)
class BudgetMeter:
    policy: BudgetPolicy
    clock: Callable[[], float] = monotonic
    started: float = field(init=False)
    turns: int = 0
    provider_calls: int = 0
    tool_calls: int = 0
    candidates: int = 0
    experiments: int = 0
    request_bytes: int = 0
    response_bytes: int = 0

    def __post_init__(self) -> None:
        self.started = self.clock()

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, self.clock() - self.started)

    @property
    def remaining_wall_seconds(self) -> float:
        return max(0.0, self.policy.max_wall_seconds - self.elapsed_seconds)

    def exhausted_reason(self, *, next_request_bytes: int = 0) -> str | None:
        checks = (
            (self.turns >= self.policy.max_turns, "MAX_TURNS"),
            (self.provider_calls >= self.policy.max_provider_calls, "MAX_PROVIDER_CALLS"),
            (
                self.request_bytes + next_request_bytes > self.policy.max_total_request_bytes,
                "MAX_TOTAL_REQUEST_BYTES",
            ),
            (next_request_bytes > self.policy.max_request_bytes, "MAX_REQUEST_BYTES"),
            (self.elapsed_seconds >= self.policy.max_wall_seconds, "MAX_WALL_SECONDS"),
        )
        return next((reason for exhausted, reason in checks if exhausted), None)

    def require_capacity(self, dimension: str, amount: int = 1) -> None:
        if dimension not in {"tool_calls", "candidates", "experiments"}:
            raise ValueError(f"Unknown budget dimension: {dimension}")
        limit = getattr(self.policy, f"max_{dimension}")
        consumed = getattr(self, dimension)
        if consumed + amount > limit:
            raise BudgetExhausted(f"MAX_{dimension.upper()}")

    def require_wall_capacity(self, seconds: float = 0.0) -> None:
        """Reject work that cannot fit in the remaining aggregate wall budget."""

        if seconds < 0:
            raise ValueError("Required wall time must be non-negative.")
        if self.remaining_wall_seconds <= 0 or seconds > self.remaining_wall_seconds:
            raise BudgetExhausted("MAX_WALL_SECONDS")

    def record_provider_call(self, request_bytes: int, response_bytes: int) -> None:
        if response_bytes > self.policy.max_response_bytes:
            raise BudgetExhausted("MAX_RESPONSE_BYTES")
        self.turns += 1
        self.provider_calls += 1
        self.request_bytes += request_bytes
        self.response_bytes += response_bytes

    def record(self, dimension: str, amount: int = 1) -> None:
        self.require_capacity(dimension, amount)
        setattr(self, dimension, getattr(self, dimension) + amount)

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": self.policy.to_dict(),
            "consumed": {
                "turns": self.turns,
                "provider_calls": self.provider_calls,
                "tool_calls": self.tool_calls,
                "candidates": self.candidates,
                "experiments": self.experiments,
                "request_bytes": self.request_bytes,
                "response_bytes": self.response_bytes,
                "elapsed_seconds": round(self.elapsed_seconds, 6),
            },
        }


class BudgetExhausted(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


__all__ = [
    "BudgetExhausted",
    "BudgetMeter",
    "BudgetPolicy",
    "DEFAULT_M0_BUDGET",
]
