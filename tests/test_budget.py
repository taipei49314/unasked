from __future__ import annotations

import pytest

from unasked.budget import BudgetExhausted, BudgetMeter, BudgetPolicy
from unasked.errors import UsageError


def _value() -> dict:
    return {
        "schema_version": "0.1.0",
        "max_turns": 2,
        "max_provider_calls": 2,
        "max_tool_calls": 1,
        "max_candidates": 1,
        "max_experiments": 1,
        "max_experiment_commands": 2,
        "max_wall_seconds": 10,
        "max_request_bytes": 100,
        "max_response_bytes": 100,
        "max_total_request_bytes": 200,
        "max_file_bytes": 100,
        "max_search_matches": 1,
        "max_inventory_entries": 10,
        "max_observations": 10,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"max_turns": -1}, "non-negative"),
        ({"max_turns": 1.5}, "non-negative"),
        ({"max_turns": True}, "non-negative"),
        ({"max_turns": 0}, "must be positive"),
        ({"unknown": 1}, "not exact"),
    ],
)
def test_budget_rejects_unbounded_or_unknown_values(mutation: dict, message: str) -> None:
    value = {**_value(), **mutation}
    with pytest.raises(UsageError, match=message):
        BudgetPolicy.from_dict(value)


def test_budget_meter_stops_before_side_effect_and_hash_is_stable() -> None:
    clock_value = [0.0]
    policy = BudgetPolicy.from_dict(_value())
    meter = BudgetMeter(policy, clock=lambda: clock_value[0])

    meter.record("tool_calls")
    with pytest.raises(BudgetExhausted) as raised:
        meter.record("tool_calls")
    assert raised.value.reason == "MAX_TOOL_CALLS"
    assert meter.tool_calls == 1
    assert policy.sha256 == BudgetPolicy.from_dict(dict(reversed(list(_value().items())))).sha256

    meter.record_provider_call(50, 20)
    assert meter.exhausted_reason(next_request_bytes=51) is None
    clock_value[0] = 10.0
    assert meter.exhausted_reason() == "MAX_WALL_SECONDS"


def test_response_limit_is_enforced_at_record_boundary() -> None:
    meter = BudgetMeter(BudgetPolicy.from_dict(_value()), clock=lambda: 0.0)
    with pytest.raises(BudgetExhausted) as raised:
        meter.record_provider_call(1, 101)
    assert raised.value.reason == "MAX_RESPONSE_BYTES"
    assert meter.provider_calls == 0
