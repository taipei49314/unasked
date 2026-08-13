from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path
from time import monotonic

import pytest

from unasked.errors import ExecutionError, IntegrityError, NotFoundError, UsageError
from unasked.providers import JsonSubprocessProvider, parse_action, provider_from_config


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


def _provider_that_leaves_a_child(
    marker: Path,
    *,
    parent_sleep: float,
    overflow: bool = False,
) -> str:
    child = (
        "import pathlib,time; "
        "time.sleep(0.75); "
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    return (
        "import subprocess,sys,time; "
        "sys.stdin.read(); "
        f"subprocess.Popen([sys.executable, '-c', {child!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True); "
        + ("sys.stdout.write('x' * 100000); sys.stdout.flush(); " if overflow else "")
        + f"time.sleep({parent_sleep})"
    )


def test_json_subprocess_provider_timeout_kills_descendant_processes(tmp_path: Path) -> None:
    marker = tmp_path / "timeout-child-survived"
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", _provider_that_leaves_a_child(marker, parent_sleep=10)],
        model_name="timeout-tree-model",
        timeout_seconds=10,
    )

    with pytest.raises(ExecutionError, match="timed out"):
        provider.invoke(
            {"request": "bounded"},
            max_output_bytes=1024,
            timeout_seconds=0.25,
        )

    time.sleep(1)
    assert not marker.exists()


def test_json_subprocess_provider_normal_exit_kills_orphan_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "successful-parent-child-survived"
    provider = JsonSubprocessProvider(
        [sys.executable, "-c", _provider_that_leaves_a_child(marker, parent_sleep=0)],
        model_name="successful-tree-model",
        timeout_seconds=10,
    )

    response = provider.invoke({"request": "bounded"}, max_output_bytes=1024)

    assert response.exit_code == 0
    time.sleep(1)
    assert not marker.exists()


def test_json_subprocess_provider_output_overflow_kills_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "overflow-child-survived"
    provider = JsonSubprocessProvider(
        [
            sys.executable,
            "-c",
            _provider_that_leaves_a_child(marker, parent_sleep=10, overflow=True),
        ],
        model_name="overflow-tree-model",
        timeout_seconds=10,
    )

    response = provider.invoke({"request": "bounded"}, max_output_bytes=1024)

    assert response.exit_code == 75
    time.sleep(1)
    assert not marker.exists()


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


def test_provider_config_base_cannot_shadow_bare_executable_from_another_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_base = tmp_path / "provider-config"
    config_base.mkdir()
    other_cwd = tmp_path / "caller"
    other_cwd.mkdir()
    bare_name = "provider-shadow"
    shadow = config_base / (f"{bare_name}.exe" if os.name == "nt" else bare_name)
    shutil.copy2(sys.executable, shadow)
    if os.name != "nt":
        shadow.chmod(shadow.stat().st_mode | 0o111)
    monkeypatch.chdir(other_cwd)
    monkeypatch.setenv("PATH", str(config_base))

    with pytest.raises(NotFoundError, match="executable was not found"):
        provider_from_config(
            {
                "kind": "json-subprocess",
                "argv": [bare_name],
                "model": "shadow-model",
            },
            base=config_base,
        )


def test_provider_config_absolute_executable_in_base_remains_allowed(tmp_path: Path) -> None:
    config_base = tmp_path / "provider-config"
    config_base.mkdir()
    executable = config_base / ("provider.exe" if os.name == "nt" else "provider")
    shutil.copy2(sys.executable, executable)
    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | 0o111)

    provider = provider_from_config(
        {
            "kind": "json-subprocess",
            "argv": [str(executable)],
            "model": "absolute-model",
        },
        base=config_base,
    )

    assert isinstance(provider, JsonSubprocessProvider)
    assert Path(provider.argv[0]) == executable.resolve()


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
