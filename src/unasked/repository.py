"""Immutable Git snapshot and clean replay helpers.

This module deliberately turns a user-facing revision (which may be symbolic) into
an object ID once, then uses only that object ID for subsequent operations.  It
does not treat a branch name as evidence of repository state.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

from unasked.errors import ExecutionError, IntegrityError, NotFoundError, UsageError
from unasked.util import sha256_bytes, utc_now

_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40,64}$")

# These names are lock or resolver outputs rather than broad dependency manifests.
_LOCKFILE_NAMES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "composer.lock",
    "deno.lock",
    "flake.lock",
    "gemfile.lock",
    "go.sum",
    "gradle.lockfile",
    "mix.lock",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "package.resolved",
    "packages.lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pubspec.lock",
    "uv.lock",
    "yarn.lock",
}


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _run_git(
    repository: str | os.PathLike[str],
    args: list[str],
    *,
    check: bool = True,
    isolated_config: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    git = shutil.which("git")
    if git is None:
        raise NotFoundError("Git executable was not found.")
    disabled_hooks = Path(tempfile.gettempdir()) / f"unasked-no-hooks-{uuid.uuid4().hex}"
    command = [
        git,
        "--no-replace-objects",
        "-c",
        f"core.hooksPath={disabled_hooks}",
        "-c",
        "core.fsmonitor=false",
        "-C",
        os.fspath(repository),
        *args,
    ]
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.upper().startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    if isolated_config:
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            shell=False,
            env=environment,
        )
    except FileNotFoundError as exc:  # pragma: no cover - executable may disappear after which()
        raise NotFoundError("Git executable was not found.") from exc
    if check and result.returncode != 0:
        raise ExecutionError(
            "Git command failed.",
            details={
                "argv": command,
                "exit_code": result.returncode,
                "stdout": _decode(result.stdout),
                "stderr": _decode(result.stderr),
            },
        )
    return result


def repository_root(repository: str | os.PathLike[str]) -> Path:
    """Return the canonical top-level path of a non-bare Git repository."""

    candidate = Path(repository).expanduser()
    if not candidate.exists():
        raise NotFoundError("Repository path does not exist.", details={"path": str(candidate)})
    result = _run_git(candidate, ["rev-parse", "--show-toplevel"])
    rendered = _decode(result.stdout).strip()
    if not rendered:
        raise IntegrityError("Git did not return a repository root.")
    return Path(rendered).resolve()


def resolve_commit(repository: str | os.PathLike[str], revision: str = "HEAD") -> str:
    """Resolve *revision* once and return a full immutable commit object ID.

    Symbolic input is accepted at this boundary for convenience.  The returned
    hexadecimal object ID, never the symbolic input, must be retained and used by
    callers as the snapshot truth.
    """

    if not isinstance(revision, str) or not revision.strip():
        raise UsageError("Git revision must be a non-empty string.")
    revision = revision.strip()
    if revision.startswith("-") or "\x00" in revision:
        raise UsageError("Git revision is not safe to pass to Git.")

    result = _run_git(repository, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
    commit = _decode(result.stdout).strip().lower()
    if not _OBJECT_ID_RE.fullmatch(commit):
        raise IntegrityError("Git returned an invalid commit object ID.", details={"value": commit})
    return commit


def assert_clean_repository(repository: str | os.PathLike[str]) -> None:
    """Reject tracked, staged, conflicted, and untracked working-tree changes."""

    root = repository_root(repository)
    result = _run_git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if result.stdout:
        entries = [_decode(entry) for entry in result.stdout.split(b"\0") if entry]
        raise IntegrityError(
            "Repository must be clean before a snapshot is captured.",
            details={"repository_path": str(root), "status": entries},
        )


# A concise compatibility name for callers that phrase this as a precondition.
require_clean_repository = assert_clean_repository


def _tree_entries(repository: Path, commit: str) -> list[tuple[str, str, str, str]]:
    """Return sorted ``(mode, type, object_id, path)`` entries for a commit."""

    raw = _run_git(repository, ["ls-tree", "-r", "-z", commit]).stdout
    entries: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", errors="surrogateescape")
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntegrityError("Unable to parse Git tree entry.") from exc
        entries.append((mode, object_type, object_id, path))
    return sorted(entries, key=lambda entry: entry[3].encode("utf-8", errors="surrogateescape"))


def _is_dependency_lock(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name in _LOCKFILE_NAMES:
        return True
    # Ecosystems frequently use scoped lock names (for example requirements.lock).
    return name.endswith((".lock", ".lock.json", ".lock.yaml", ".lock.yml"))


def _git_blob(repository: Path, object_id: str) -> bytes:
    return _run_git(repository, ["cat-file", "blob", object_id]).stdout


def capture_snapshot(
    repository: str | os.PathLike[str],
    revision: str = "HEAD",
    *,
    require_clean: bool = True,
) -> dict[str, Any]:
    """Capture immutable, JSON-serializable metadata for a Git commit.

    The function is intentionally metadata-only: no repository files are changed,
    no submodule is initialized, and no remote is contacted.
    """

    root = repository_root(repository)
    if require_clean:
        assert_clean_repository(root)

    commit = resolve_commit(root, revision)
    tree = _decode(_run_git(root, ["rev-parse", f"{commit}^{{tree}}"]).stdout).strip()
    if not _OBJECT_ID_RE.fullmatch(tree):
        raise IntegrityError("Git returned an invalid tree object ID.", details={"tree": tree})

    submodules: list[dict[str, str]] = []
    dependency_locks: list[dict[str, str]] = []
    for mode, object_type, object_id, path in _tree_entries(root, commit):
        if mode == "160000" and object_type == "commit":
            submodules.append({"path": path, "commit": object_id})
        elif object_type == "blob" and _is_dependency_lock(path):
            dependency_locks.append(
                {
                    "path": path,
                    "git_blob": object_id,
                    "sha256": sha256_bytes(_git_blob(root, object_id)),
                }
            )

    git_version_result = _run_git(root, ["--version"])
    snapshot: dict[str, Any] = {
        "repository_path": str(root),
        "commit": commit,
        "tree": tree,
        "submodules": submodules,
        "dependency_locks": dependency_locks,
        "captured_at": utc_now(),
        "git_version": _decode(git_version_result.stdout).strip(),
        "target_type": "immutable_git_commit",
    }

    # A change during capture invalidates the clean-snapshot precondition.  All
    # metadata above is nevertheless bound to ``commit``, not to a branch name.
    if require_clean:
        assert_clean_repository(root)
    return snapshot


def list_snapshot_files(
    repository: str | os.PathLike[str],
    commit: str,
) -> list[dict[str, Any]]:
    """List immutable tree entries without reading mutable worktree bytes.

    The returned inventory is deliberately small enough to expose to an Explorer:
    paths, Git object identities, modes, and byte sizes.  It contains no branch
    names and never contacts a remote.
    """

    root = repository_root(repository)
    pinned_commit = resolve_commit(root, commit)
    if pinned_commit != commit.lower():
        raise IntegrityError("Snapshot commit must be a full immutable object ID.")
    inventory: list[dict[str, Any]] = []
    for mode, object_type, object_id, path in _tree_entries(root, pinned_commit):
        if object_type == "blob":
            size = len(_git_blob(root, object_id))
        elif mode == "160000" and object_type == "commit":
            size = len(object_id)
        else:
            continue
        inventory.append(
            {
                "path": path,
                "mode": mode,
                "object_type": object_type,
                "object_id": object_id,
                "size_bytes": size,
            }
        )
    return inventory


def read_snapshot_file(
    repository: str | os.PathLike[str],
    commit: str,
    path: str,
) -> bytes:
    """Read one exact blob from an immutable commit.

    ``path`` is matched as data against the parsed Git tree.  It is never passed
    to a shell or interpreted as a revision expression.
    """

    if not isinstance(path, str) or not path or "\x00" in path:
        raise UsageError("Snapshot path must be a non-empty UTF-8 path.")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != path:
        raise UsageError("Snapshot path must be a normalized relative POSIX path.")
    root = repository_root(repository)
    pinned_commit = resolve_commit(root, commit)
    if pinned_commit != commit.lower():
        raise IntegrityError("Snapshot commit must be a full immutable object ID.")
    for mode, object_type, object_id, entry_path in _tree_entries(root, pinned_commit):
        if entry_path != path:
            continue
        if object_type != "blob" or mode == "160000":
            raise UsageError("Snapshot entry is not a readable file.", details={"path": path})
        return _git_blob(root, object_id)
    raise NotFoundError("Snapshot file was not found.", details={"path": path})


@contextlib.contextmanager
def temporary_worktree(
    repository: str | os.PathLike[str],
    commit: str,
    *,
    parent: str | os.PathLike[str] | None = None,
    require_source_clean: bool = True,
) -> Iterator[Path]:
    """Yield a detached, clean temporary repository pinned to *commit*.

    The checkout is created from a new repository that borrows only the source
    object database.  It never loads the source repository's hooks, filters, or
    local Git configuration.  Submodules are not initialized because doing so may
    contact a network.  Their pinned Gitlink object IDs are available from
    :func:`capture_snapshot`.
    """

    root = repository_root(repository)
    if require_source_clean:
        assert_clean_repository(root)
    pinned_commit = resolve_commit(root, commit)

    parent_path: Path | None = None
    if parent is not None:
        parent_path = Path(parent).expanduser().resolve()
        parent_path.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(tempfile.mkdtemp(prefix="unasked-worktree-", dir=parent_path)).resolve()
    worktree = temporary_root / "checkout"
    body_error: BaseException | None = None
    try:
        common_raw = _decode(_run_git(root, ["rev-parse", "--git-common-dir"]).stdout).strip()
        common_dir = Path(common_raw)
        if not common_dir.is_absolute():
            common_dir = (root / common_dir).resolve()
        object_directory = (common_dir / "objects").resolve()
        if not object_directory.is_dir():
            raise IntegrityError(
                "Source Git object directory was not found.",
                details={"path": str(object_directory)},
            )

        worktree.mkdir(parents=True)
        _run_git(worktree, ["init", "--quiet"], isolated_config=True)
        alternates = worktree / ".git" / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_bytes(object_directory.as_posix().encode("utf-8") + b"\n")
        _run_git(worktree, ["config", "core.autocrlf", "false"], isolated_config=True)
        _run_git(worktree, ["config", "core.fsmonitor", "false"], isolated_config=True)
        _run_git(
            worktree,
            ["config", "core.hooksPath", str(temporary_root / "no-hooks")],
            isolated_config=True,
        )
        _run_git(
            worktree,
            ["checkout", "--detach", "--force", pinned_commit],
            isolated_config=True,
        )
        actual = resolve_commit(worktree, "HEAD")
        if actual != pinned_commit:
            raise IntegrityError(
                "Temporary worktree is not pinned to the requested commit.",
                details={"expected": pinned_commit, "actual": actual},
            )
        assert_clean_repository(worktree)
        yield worktree
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            shutil.rmtree(temporary_root)
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup_error = cleanup_error or exc
        if cleanup_error is not None and body_error is None:
            raise cleanup_error


# Compatibility aliases that preserve the context-manager semantics.
clean_worktree = temporary_worktree
create_clean_worktree = temporary_worktree


__all__ = [
    "assert_clean_repository",
    "capture_snapshot",
    "clean_worktree",
    "create_clean_worktree",
    "list_snapshot_files",
    "read_snapshot_file",
    "repository_root",
    "require_clean_repository",
    "resolve_commit",
    "temporary_worktree",
]
