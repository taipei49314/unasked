from __future__ import annotations

import json
from pathlib import Path

import pytest

from unasked.errors import UsageError
from unasked.protocol import load_protocol, protocol_hash


def test_default_protocol_hash_is_stable() -> None:
    first = load_protocol()
    second = load_protocol()
    assert protocol_hash(first) == protocol_hash(second)
    assert first is not second
    assert first["false_verified_claim_rate_target"] == 0


def test_protocol_rejects_gate_registry_drift(tmp_path) -> None:
    protocol = load_protocol()
    protocol["verified_requires"] = protocol["verified_requires"][:-1]
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(protocol), encoding="utf-8")
    with pytest.raises(UsageError, match="exactly match"):
        load_protocol(path)


def test_m0_development_protocol_is_explicitly_non_certifying() -> None:
    path = Path(__file__).resolve().parents[1] / "protocols" / "m0-development-v0.1.json"

    protocol = load_protocol(path)

    assert protocol["evaluation_status"] == "UNSEALED_DEVELOPMENT"
    assert protocol["formal_m0_eligible"] is False
    assert protocol["verified_requires"] == load_protocol()["verified_requires"]
