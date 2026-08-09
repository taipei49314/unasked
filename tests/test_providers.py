from __future__ import annotations

import sys
from pathlib import Path
from time import monotonic

import pytest

from unasked.errors import ExecutionError, IntegrityError, UsageError
from unasked.providers import JsonSubprocessProvider, parse_action


def test_json_subprocess_provider_strips_secrets_and_returns_one_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("UNASKED_TEST_SECRET", "must-not-cross")
    script = (
        "import json,os,sys; json.load(sys.stdin); "
        "print(json.dumps({'action':'STOP','reason':"
        "'LEAK' if 'UNASKED_TEST_SECRET' in os.environ else 'CLEAN'}))"
    )
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", script],
        model_name="fixture-local-model",
        timeout_seconds=10,
    )
    response = provider.invoke({"request": "bounded"}, max_output_bytes=4096)

    assert response.exit_code == 0
    assert parse_action(response.stdout) == {"action": "STOP", "reason": "CLEAN"}
    assert provider.metadata["network_isolation_enforced"] is False
    assert "-c" not in str(provider.metadata)


def test_json_subprocess_provider_kills_output_overflow() -> None:
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", "import sys; sys.stdin.read(); print('x' * 100000)"],
        model_name="overflow-model",
        timeout_seconds=10,
    )
    response = provider.invoke({"request": "bounded"}, max_output_bytes=1024)

    assert response.exit_code == 75
    assert len(response.stdout) + len(response.stderr) <= 1024


def test_json_subprocess_provider_applies_one_combined_output_cap() -> None:
    script = (
        "import json,sys; sys.stdin.read(); "
        "print(json.dumps({'action':'STOP'})); "
        "sys.stderr.write('x' * 100000)"
    )
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", script],
        model_name="combined-output-model",
        timeout_seconds=10,
    )

    response = provider.invoke({"request": "bounded"}, max_output_bytes=1024)

    assert response.exit_code == 75
    assert len(response.stdout) + len(response.stderr) <= 1024


def test_json_subprocess_provider_honors_smaller_budget_timeout() -> None:
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", "import sys,time; sys.stdin.read(); time.sleep(3)"],
        model_name="timeout-model",
        timeout_seconds=10,
    )
    started = monotonic()

    with pytest.raises(ExecutionError, match="timed out"):
        provider.invoke(
            {"request": "bounded"},
            max_output_bytes=1024,
            timeout_seconds=0.25,
        )

    assert monotonic() - started < 2


def test_json_subprocess_provider_rechecks_bound_files(tmp_path: Path) -> None:
    script = tmp_path / "provider.py"
    script.write_text('print(\'{"action":"STOP"}\')\n', encoding="utf-8")
    provider = JsonSubprocessProvider(
        [sys.executable, str(script)],
        model_name="bound-model",
        bound_files=[script],
    )
    script.write_text('print(\'{"action":"STOP","reason":"changed"}\')\n', encoding="utf-8")

    with pytest.raises(IntegrityError, match="bound file changed"):
        provider.invoke({"request": "bounded"}, max_output_bytes=1024)


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"action":"STOP"}{"action":"STOP"}',
        b"\xff",
    ],
)
def test_provider_parser_rejects_non_single_object_output(raw: bytes) -> None:
    with pytest.raises(UsageError):
        parse_action(raw)
