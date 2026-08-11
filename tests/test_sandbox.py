from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from unasked.errors import PolicyError, UsageError
from unasked.sandbox import RestrictedExecutor


def _executor(worktree: Path, timeout: float = 5.0) -> RestrictedExecutor:
    return RestrictedExecutor(
        worktree,
        allowed_executables=[sys.executable],
        timeout_seconds=timeout,
    )


def test_executor_records_argv_output_and_local_restriction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "worktree"
    child = worktree / "child"
    child.mkdir(parents=True)
    monkeypatch.setenv("UNASKED_TEST_TOKEN", "must-not-reach-child")
    executor = _executor(worktree)
    argv = [
        sys.executable,
        "-c",
        "import os; print(os.getcwd()); print(os.getenv('UNASKED_TEST_TOKEN', 'stripped'))",
    ]

    result = executor.execute(argv, cwd="child")

    assert result["argv"] == argv
    assert result["cwd"] == str(child.resolve())
    assert result["exit_code"] == 0
    assert not result["timed_out"]
    assert "stripped" in result["stdout"]
    assert "must-not-reach-child" not in result["stdout"]
    assert "UNASKED_TEST_TOKEN" in result["stripped_env_keys"]
    assert result["shell"] is False
    assert result["isolation"] == "local_restricted"
    assert result["network_isolated"] is False
    assert "not network-isolated" in result["isolation_notice"]
    assert result["duration_seconds"] >= 0


def test_executor_rejects_path_escape(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    executor = _executor(worktree)

    with pytest.raises(PolicyError, match="escapes"):
        executor.execute([sys.executable, "-c", "print('no')"], cwd=worktree.parent)


def test_executor_rejects_disallowed_executable_and_command_string(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    executor = _executor(worktree)

    with pytest.raises(PolicyError, match="allowlisted"):
        executor.execute(["git", "status"])
    with pytest.raises(UsageError, match="argv list"):
        executor.execute("git status")  # type: ignore[arg-type]
    with pytest.raises(PolicyError, match="Shell execution"):
        executor.execute([sys.executable, "-V"], shell=True)


def test_executor_returns_a_timeout_record(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    executor = _executor(worktree, timeout=0.1)

    result = executor.execute([sys.executable, "-c", "import time; time.sleep(2)"])

    assert result["timed_out"] is True
    assert result["exit_code"] is None
    assert result["timeout_seconds"] == 0.1


def test_executor_rejects_secret_and_launch_environment_overrides(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    executor = _executor(worktree)

    result = executor.execute(
        [sys.executable, "-c", "import os; print(os.getenv('API_TOKEN', 'missing'))"],
        env={"API_TOKEN": "secret"},
    )
    assert result["stdout"].strip() == "missing"
    assert "API_TOKEN" in result["stripped_env_keys"]

    with pytest.raises(PolicyError, match="Launch environment"):
        executor.execute([sys.executable, "-V"], env={"PATH": os.devnull})


def test_executor_does_not_resolve_bare_names_from_the_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    executable_name = Path(sys.executable).stem
    if os.name == "nt":
        fake = worktree / f"{executable_name}.cmd"
        fake.write_text("@echo off\r\necho attacker\r\n", encoding="utf-8")
    else:
        fake = worktree / executable_name
        fake.write_text("#!/bin/sh\necho attacker\n", encoding="utf-8")
        fake.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join((".", os.environ.get("PATH", ""))))
    monkeypatch.chdir(worktree)
    executor = RestrictedExecutor(worktree, allowed_executables=[executable_name])

    result = executor.execute([executable_name, "-c", "print('trusted')"])

    assert result["stdout"].strip() == "trusted"
    assert Path(result["resolved_executable"]).resolve() == Path(sys.executable).resolve()
