from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import unasked.repository as repository_module
from unasked.errors import ExecutionError, IntegrityError
from unasked.repository import (
    capture_snapshot,
    read_snapshot_file,
    resolve_commit,
    temporary_worktree,
)


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=UNASKED Test",
        "-c",
        "user.email=unasked@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / "README.md").write_text("# Fixture\n\nPinned content.\n", encoding="utf-8")
    (root / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
    _commit(root, "initial")
    return root


def test_capture_snapshot_pins_commit_and_hashes_locks(repository: Path) -> None:
    expected_commit = _git(repository, "rev-parse", "HEAD")
    expected_tree = _git(repository, "rev-parse", "HEAD^{tree}")

    snapshot = capture_snapshot(repository, "HEAD")

    assert snapshot["commit"] == expected_commit
    assert snapshot["tree"] == expected_tree
    assert re.fullmatch(r"[0-9a-f]{40,64}", snapshot["commit"])
    assert snapshot["target_type"] == "immutable_git_commit"
    assert snapshot["repository_path"] == str(repository.resolve())
    assert snapshot["git_version"].startswith("git version ")
    assert snapshot["submodules"] == []
    assert snapshot["dependency_locks"] == [
        {
            "path": "package-lock.json",
            "git_blob": _git(repository, "rev-parse", "HEAD:package-lock.json"),
            "sha256": hashlib.sha256(b'{"lockfileVersion":3}\n').hexdigest(),
        }
    ]
    # Public snapshot output must be directly serializable for an evidence record.
    json.dumps(snapshot)


def test_capture_snapshot_rejects_a_dirty_worktree(repository: Path) -> None:
    (repository / "untracked.txt").write_text("not part of the commit", encoding="utf-8")

    with pytest.raises(IntegrityError, match="clean"):
        capture_snapshot(repository)


def test_clean_check_never_loads_repository_filter_commands(repository: Path) -> None:
    attributes = repository / ".gitattributes"
    attributes.write_text("*.md filter=unasked-security\n", encoding="utf-8")
    _commit(repository, "add filter attribute")
    _git(
        repository,
        "config",
        "filter.unasked-security.clean",
        "unasked-filter-command-that-must-not-run",
    )
    readme = repository / "README.md"
    readme.write_bytes(readme.read_bytes())
    current = readme.stat()
    os.utime(readme, ns=(current.st_atime_ns, current.st_mtime_ns + 2_000_000_000))

    snapshot = capture_snapshot(repository)

    assert snapshot["commit"] == _git(repository, "rev-parse", "HEAD")


def test_snapshot_does_not_parse_source_config_includes(
    repository: Path,
    tmp_path: Path,
) -> None:
    expected = _git(repository, "rev-parse", "HEAD")
    invalid_include = tmp_path / "invalid-source-config"
    invalid_include.write_text("[malformed\n", encoding="utf-8")
    _git(repository, "config", "include.path", str(invalid_include))

    snapshot = capture_snapshot(repository)

    assert snapshot["commit"] == expected


def test_source_core_worktree_cannot_redirect_repository_root(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    _git(repository, "config", "core.worktree", str(outside))

    snapshot = capture_snapshot(repository)

    assert snapshot["repository_path"] == str(repository.resolve())


def test_source_object_database_links_are_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    external = tmp_path / "external-object"
    external.write_bytes(b"not a Git object")
    loose_directory = repository / ".git" / "objects" / "aa"
    loose_directory.mkdir()
    link = loose_directory / ("b" * 38)
    try:
        link.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"file links are not available: {exc}")

    with pytest.raises(IntegrityError, match="object database.*links"):
        capture_snapshot(repository)


def test_temporary_worktree_reuses_git_selected_with_source_excluded(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_git = shutil.which("git")
    assert real_git is not None
    shadow = repository / ("git.exe" if os.name == "nt" else "git")
    shadow.write_bytes(b"not a trusted Git executable")
    if os.name != "nt":
        shadow.chmod(0o755)
    pinned = _commit(repository, "add PATH shadow")
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join((str(repository), str(Path(real_git).resolve().parent))),
    )

    with temporary_worktree(repository, pinned) as worktree:
        assert (worktree / shadow.name).read_bytes() == shadow.read_bytes()


def test_temporary_cleanup_never_follows_a_replaced_checkout_link(tmp_path: Path) -> None:
    temporary_root = tmp_path / "unasked-worktree-fixture"
    temporary_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("preserve\n", encoding="utf-8")
    checkout = temporary_root / "checkout"
    try:
        checkout.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory links are not available: {exc}")

    repository_module._remove_tree_without_following_links(temporary_root)

    assert not temporary_root.exists()
    assert secret.read_text(encoding="utf-8") == "preserve\n"


def test_clean_worktree_replays_the_pinned_commit(repository: Path) -> None:
    pinned = resolve_commit(repository, "HEAD")
    (repository / "README.md").write_text("# Fixture\n\nNewer content.\n", encoding="utf-8")
    newer = _commit(repository, "newer")
    assert newer != pinned

    replay_path: Path | None = None
    with temporary_worktree(repository, pinned) as worktree:
        replay_path = worktree
        assert _git(worktree, "rev-parse", "HEAD") == pinned
        assert _git(worktree, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD"
        assert _git(worktree, "status", "--porcelain=v1", "--untracked-files=all") == ""
        assert "Pinned content." in (worktree / "README.md").read_text(encoding="utf-8")

    assert replay_path is not None
    assert not replay_path.exists()


def test_snapshot_reads_ignore_git_replace_refs(repository: Path) -> None:
    pinned = resolve_commit(repository, "HEAD")
    (repository / "README.md").write_text("# Fixture\n\nReplacement content.\n", encoding="utf-8")
    replacement = _commit(repository, "replacement")
    _git(repository, "replace", pinned, replacement)

    # Ordinary Git porcelain follows the attacker-controlled replacement ref.
    assert "Replacement content." in _git(repository, "show", f"{pinned}:README.md")
    assert b"Pinned content." in read_snapshot_file(repository, pinned, "README.md")
    with temporary_worktree(repository, pinned) as worktree:
        assert "Pinned content." in (worktree / "README.md").read_text(encoding="utf-8")


def test_temporary_checkout_does_not_execute_source_repository_hooks(
    repository: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "source-hook-ran"
    hook = repository / ".git" / "hooks" / "post-checkout"
    hook.write_text(
        f"#!/bin/sh\nprintf invoked > '{marker.as_posix()}'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)

    with temporary_worktree(repository, resolve_commit(repository, "HEAD")) as worktree:
        assert (worktree / "README.md").is_file()

    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows current-directory executable lookup")
def test_git_resolution_ignores_repository_git_cmd(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "attacker-git-ran"
    expected = _git(repository, "rev-parse", "HEAD")
    (repository / "git.cmd").write_text(
        f"@echo off\r\necho invoked>{marker}\r\nexit /b 0\r\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repository)

    assert resolve_commit(repository, "HEAD") == expected
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows PATH executable lookup")
def test_git_resolution_excludes_repository_root_when_called_from_subdirectory(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = _git(repository, "rev-parse", "HEAD")
    subdirectory = repository / "nested"
    subdirectory.mkdir()
    (repository / "git.exe").write_bytes(b"not a real executable")
    monkeypatch.setenv("PATH", os.pathsep.join((str(repository), os.environ.get("PATH", ""))))

    assert resolve_commit(subdirectory, "HEAD") == expected


def test_git_subprocess_disables_lazy_fetch_and_interaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured_environment: dict[str, str] = {}
    captured_command: list[str] = []

    def fake_run(command, **kwargs):
        captured_command.extend(command)
        captured_environment.update(kwargs["env"])
        return subprocess.CompletedProcess([], 0, stdout=b"git version fixture\n", stderr=b"")

    monkeypatch.setattr(
        repository_module,
        "find_executable",
        lambda *args, **kwargs: Path(sys.executable).resolve(strict=True),
    )
    monkeypatch.setattr(repository_module.subprocess, "run", fake_run)

    repository_module._run_git(tmp_path, ["--version"])

    assert "--no-lazy-fetch" in captured_command
    assert captured_environment["GIT_NO_LAZY_FETCH"] == "1"
    assert captured_environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert captured_environment["GIT_TERMINAL_PROMPT"] == "0"
    assert captured_environment["GCM_INTERACTIVE"] == "Never"


def test_partial_clone_missing_blob_fails_without_contacting_remote(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    (source / "payload.bin").write_bytes(b"partial-clone-fixture" * 1024)
    _commit(source, "add payload")
    bare = tmp_path / "remote.git"
    subprocess.run(
        ["git", "clone", "--bare", "--quiet", str(source), str(bare)],
        check=True,
        capture_output=True,
    )
    _git(bare, "config", "uploadpack.allowFilter", "true")
    partial = tmp_path / "partial"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--no-checkout",
            bare.as_uri(),
            str(partial),
        ],
        check=True,
        capture_output=True,
    )
    commit = _git(partial, "rev-parse", "HEAD")
    bare.rename(tmp_path / "remote-offline.git")

    with pytest.raises(ExecutionError, match="Git command failed"):
        read_snapshot_file(partial, commit, "payload.bin")
