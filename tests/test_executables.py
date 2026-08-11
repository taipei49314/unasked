from __future__ import annotations

import os
from pathlib import Path

import pytest

from unasked.executables import _normalize_windows_namespace, find_executable


def _fake_executable(directory: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    path = directory / f"{name}{suffix}"
    path.write_bytes(b"not actually executed")
    if os.name != "nt":
        path.chmod(0o755)
    return path


def test_resolver_ignores_empty_relative_and_excluded_path_entries(tmp_path: Path) -> None:
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    fake = _fake_executable(attacker, "unasked-fixture-tool")

    relative_path = os.pathsep.join(("", ".", str(attacker.relative_to(tmp_path))))
    assert find_executable("unasked-fixture-tool", path=relative_path) is None
    assert find_executable("unasked-fixture-tool", path=str(attacker)) == fake.resolve()
    assert (
        find_executable(
            "unasked-fixture-tool",
            path=str(attacker),
            excluded_roots=(attacker,),
        )
        is None
    )


def test_resolver_rejects_a_symlink_candidate_originating_inside_excluded_root(
    tmp_path: Path,
) -> None:
    attacker = tmp_path / "attacker"
    trusted = tmp_path / "trusted"
    attacker.mkdir()
    trusted.mkdir()
    target = _fake_executable(trusted, "unasked-symlink-fixture-tool")
    link = attacker / target.name
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlinks are not available: {exc}")

    assert (
        find_executable(
            "unasked-symlink-fixture-tool",
            path=str(attacker),
            excluded_roots=(attacker,),
        )
        is None
    )


def test_windows_extended_namespace_is_normalized() -> None:
    assert _normalize_windows_namespace(r"\\?\C:\repo\tool.exe") == r"C:\repo\tool.exe"
    assert _normalize_windows_namespace(r"\\?\UNC\server\share\tool.exe") == (
        r"\\server\share\tool.exe"
    )


@pytest.mark.skipif(os.name != "nt", reason="Win32 extended-length namespace regression")
def test_resolver_rejects_extended_namespace_alias_of_excluded_root(tmp_path: Path) -> None:
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _fake_executable(attacker, "unasked-namespace-fixture-tool")
    extended = rf"\\?\{attacker}"

    assert (
        find_executable(
            "unasked-namespace-fixture-tool",
            path=extended,
            excluded_roots=(attacker,),
        )
        is None
    )
