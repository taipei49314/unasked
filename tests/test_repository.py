from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

from unasked.errors import IntegrityError
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
