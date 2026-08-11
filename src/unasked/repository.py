"""Immutable Git snapshot and clean replay helpers.

This module deliberately turns a user-facing revision (which may be symbolic) into
an object ID once, then uses only that object ID for subsequent operations.  It
does not treat a branch name as evidence of repository state.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import stat
import subprocess  # nosec B404
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from unasked.errors import ExecutionError, IntegrityError, NotFoundError, UsageError
from unasked.executables import _normalize_windows_namespace, find_executable
from unasked.util import sha256_bytes, sha256_file, utc_now

_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40,64}$")
_MAX_METADATA_BYTES = 16 * 1024 * 1024
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


@dataclass(frozen=True)
class _TrustedGit:
    path: Path
    identity: tuple[int, int, int, int, int]
    sha256: str

    def verify(self) -> None:
        current = _executable_identity(self.path)
        if current != self.identity or sha256_file(self.path) != self.sha256:
            raise IntegrityError("The trusted Git executable changed during the operation.")


@dataclass(frozen=True)
class _RepositoryLayout:
    root: Path
    git_dir: Path
    common_dir: Path
    object_directory: Path
    object_format: str


def _is_reparse_point(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _executable_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NotFoundError("Git executable was not found.") from exc
    if _is_reparse_point(value) or not stat.S_ISREG(value.st_mode):
        raise IntegrityError("The trusted Git executable is not a regular file.")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)


def _freeze_trusted_git(repository: str | os.PathLike[str]) -> _TrustedGit:
    git_path = find_executable(
        "git",
        path=os.environ.get("PATH"),
        excluded_roots=_repository_search_exclusions(repository),
        windows_suffixes=(".exe",),
    )
    if git_path is None:
        raise NotFoundError("Git executable was not found.")
    identity_before = _executable_identity(git_path)
    digest = sha256_file(git_path)
    identity_after = _executable_identity(git_path)
    if identity_before != identity_after:
        raise IntegrityError("The trusted Git executable changed while it was selected.")
    return _TrustedGit(git_path, identity_after, digest)


def _read_regular_metadata(
    path: Path,
    *,
    required: bool = True,
    limit: int = _MAX_METADATA_BYTES,
) -> bytes | None:
    try:
        value = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise IntegrityError(
                "Required Git metadata is missing.", details={"path": str(path)}
            ) from None
        return None
    except OSError as exc:
        raise IntegrityError(
            "Unable to inspect Git metadata.", details={"path": str(path)}
        ) from exc
    if _is_reparse_point(value) or not stat.S_ISREG(value.st_mode) or value.st_size > limit:
        raise IntegrityError(
            "Git metadata must be a bounded regular file.", details={"path": str(path)}
        )
    payload = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    if (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise IntegrityError("Git metadata changed while it was read.")
    return payload


def _local_metadata_path(base: Path, rendered: str) -> Path:
    value = _normalize_windows_namespace(rendered.strip()) if os.name == "nt" else rendered.strip()
    if not value or "\x00" in value or (os.name == "nt" and value.startswith("\\\\")):
        raise IntegrityError("Git metadata points to a remote or invalid path.")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        return candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise IntegrityError("Git metadata path could not be resolved locally.") from exc


def _config_value(raw: bytes, section: str, key: str) -> str | None:
    current = ""
    for raw_line in raw.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].split('"', 1)[0].strip().casefold()
            continue
        if current != section.casefold() or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip().casefold() == key.casefold():
            return value.strip()
    return None


def _validate_local_object_database(root: Path) -> None:
    pending = [root]
    while pending:
        directory = pending.pop()
        before = directory.stat(follow_symlinks=False)
        if _is_reparse_point(before) or not stat.S_ISDIR(before.st_mode):
            raise IntegrityError("The Git object database contains a linked directory.")
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise IntegrityError("Unable to enumerate the Git object database.") from exc
        for entry in entries:
            path = Path(entry.path)
            value = path.stat(follow_symlinks=False)
            if _is_reparse_point(value):
                raise IntegrityError("The Git object database must not contain links.")
            if stat.S_ISDIR(value.st_mode):
                pending.append(path)
            elif not stat.S_ISREG(value.st_mode):
                raise IntegrityError("The Git object database has an unsupported file type.")
        after = directory.stat(follow_symlinks=False)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_mtime_ns,
        ):
            raise IntegrityError("The Git object database changed while it was inspected.")


def _repository_layout(repository: str | os.PathLike[str]) -> _RepositoryLayout:
    rendered = os.path.expanduser(os.path.expandvars(os.fspath(repository)))
    if os.name == "nt":
        rendered = _normalize_windows_namespace(rendered)
        if rendered.startswith("\\\\"):
            raise IntegrityError("Remote repository paths are not supported.")
    candidate = Path(rendered)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        candidate = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise NotFoundError(
            "Repository path does not exist.", details={"path": str(candidate)}
        ) from exc
    if not candidate.is_dir():
        raise NotFoundError("Repository path is not a directory.")

    root: Path | None = None
    marker: Path | None = None
    for ancestor in (candidate, *candidate.parents):
        possible = ancestor / ".git"
        try:
            possible.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise IntegrityError("Unable to inspect the repository marker.") from exc
        root = ancestor
        marker = possible
        break
    if root is None or marker is None:
        raise NotFoundError("Path is not inside a non-bare Git repository.")

    marker_stat = marker.stat(follow_symlinks=False)
    if _is_reparse_point(marker_stat):
        raise IntegrityError("The repository marker must not be a link or reparse point.")
    if stat.S_ISDIR(marker_stat.st_mode):
        git_dir = marker.resolve(strict=True)
    elif stat.S_ISREG(marker_stat.st_mode):
        marker_bytes = _read_regular_metadata(marker, limit=4096)
        if marker_bytes is None:
            raise IntegrityError(
                "Required Git directory metadata is missing.",
                details={"path": str(marker)},
            )
        try:
            marker_text = marker_bytes.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise IntegrityError("The Git directory marker is not UTF-8.") from exc
        if not marker_text.casefold().startswith("gitdir:"):
            raise IntegrityError("The Git directory marker is malformed.")
        git_dir = _local_metadata_path(root, marker_text.split(":", 1)[1])
    else:
        raise IntegrityError("The repository marker has an unsupported type.")
    git_dir_stat = git_dir.stat(follow_symlinks=False)
    if _is_reparse_point(git_dir_stat) or not stat.S_ISDIR(git_dir_stat.st_mode):
        raise IntegrityError("The Git metadata directory must be a local directory.")

    commondir_bytes = _read_regular_metadata(git_dir / "commondir", required=False, limit=4096)
    if commondir_bytes is None:
        common_dir = git_dir
    else:
        try:
            commondir_text = commondir_bytes.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise IntegrityError("The Git common directory marker is not UTF-8.") from exc
        common_dir = _local_metadata_path(git_dir, commondir_text)
    common_stat = common_dir.stat(follow_symlinks=False)
    if _is_reparse_point(common_stat) or not stat.S_ISDIR(common_stat.st_mode):
        raise IntegrityError("The Git common directory must be a local directory.")

    object_directory = common_dir / "objects"
    object_stat = object_directory.stat(follow_symlinks=False)
    if _is_reparse_point(object_stat) or not stat.S_ISDIR(object_stat.st_mode):
        raise IntegrityError("The Git object database must be a local directory.")
    source_alternates = object_directory / "info" / "alternates"
    try:
        source_alternates.stat(follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise IntegrityError("Unable to inspect Git object database alternates.") from exc
    else:
        raise IntegrityError(
            "Git object database alternates are not accepted from source metadata."
        )
    _validate_local_object_database(object_directory)

    config = _read_regular_metadata(common_dir / "config", required=False) or b""
    object_format = (_config_value(config, "extensions", "objectformat") or "sha1").casefold()
    if object_format not in {"sha1", "sha256"}:
        raise IntegrityError("The Git repository uses an unsupported object format.")
    ref_storage = _config_value(config, "extensions", "refstorage")
    if ref_storage not in {None, "files"}:
        raise IntegrityError("Only the Git files reference backend is supported.")
    return _RepositoryLayout(root, git_dir, common_dir, object_directory, object_format)


def _repository_search_exclusions(repository: str | os.PathLike[str]) -> tuple[Path, ...]:
    candidate = Path(repository).expanduser().resolve(strict=False)
    roots = [candidate, Path.cwd().resolve()]
    for ancestor in (candidate, *candidate.parents):
        marker = ancestor / ".git"
        if marker.exists() or marker.is_symlink():
            roots.append(ancestor)
            break
    return tuple(dict.fromkeys(roots))


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.upper().startswith("GIT_"):
            environment.pop(name, None)
    environment.update(
        {
            "GCM_INTERACTIVE": "Never",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _spawn_git(
    repository: Path,
    args: list[str],
    *,
    git: _TrustedGit,
    check: bool,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    git.verify()
    disabled_hooks = Path(tempfile.gettempdir()) / f"unasked-no-hooks-{uuid.uuid4().hex}"
    command = [
        str(git.path),
        "--no-replace-objects",
        "--no-lazy-fetch",
        "-c",
        f"core.hooksPath={disabled_hooks}",
        "-c",
        "core.fsmonitor=false",
    ]
    if git_dir is None:
        command.extend(("-C", os.fspath(repository)))
    else:
        command.extend((f"--git-dir={git_dir}", f"--work-tree={work_tree or repository}"))
    command.extend(args)
    try:
        # TrustedGit pins executable identity and digest; shell execution is disabled.
        result = subprocess.run(  # nosec B603
            command,
            check=False,
            capture_output=True,
            shell=False,
            env=_git_environment(),
        )
    except FileNotFoundError as exc:  # pragma: no cover - executable may disappear after which()
        raise NotFoundError("Git executable was not found.") from exc
    git.verify()
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


def _copy_metadata_tree(source: Path, destination: Path) -> None:
    try:
        source_stat = source.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if _is_reparse_point(source_stat) or not stat.S_ISDIR(source_stat.st_mode):
        raise IntegrityError("Git reference metadata must be a regular directory tree.")
    pending = [(source, destination)]
    while pending:
        current_source, current_destination = pending.pop()
        current_destination.mkdir(parents=True, exist_ok=True)
        try:
            entries = list(os.scandir(current_source))
        except OSError as exc:
            raise IntegrityError("Unable to enumerate Git reference metadata.") from exc
        for entry in entries:
            path = Path(entry.path)
            value = path.stat(follow_symlinks=False)
            target = current_destination / entry.name
            if _is_reparse_point(value):
                raise IntegrityError("Git reference metadata must not contain links.")
            if stat.S_ISDIR(value.st_mode):
                pending.append((path, target))
            elif stat.S_ISREG(value.st_mode):
                payload = _read_regular_metadata(path)
                if payload is None:
                    raise IntegrityError(
                        "Required Git reference metadata is missing.",
                        details={"path": str(path)},
                    )
                target.write_bytes(payload)
            else:
                raise IntegrityError("Git reference metadata has an unsupported file type.")


@contextlib.contextmanager
def _safe_repository_view(
    layout: _RepositoryLayout,
    git: _TrustedGit,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="unasked-git-view-") as temporary:
        safe_root = Path(temporary).resolve() / "repository"
        safe_root.mkdir()
        empty_template = Path(temporary).resolve() / "empty-template"
        empty_template.mkdir()
        init_args = ["init", "--quiet", f"--template={empty_template}"]
        if layout.object_format == "sha256":
            init_args.append("--object-format=sha256")
        _spawn_git(safe_root, init_args, git=git, check=True)
        safe_git_dir = safe_root / ".git"
        head = _read_regular_metadata(layout.git_dir / "HEAD", limit=4096)
        if head is None:
            raise IntegrityError(
                "Required Git HEAD metadata is missing.",
                details={"path": str(layout.git_dir / "HEAD")},
            )
        (safe_git_dir / "HEAD").write_bytes(head)
        _copy_metadata_tree(layout.common_dir / "refs", safe_git_dir / "refs")
        for filename in ("packed-refs", "shallow"):
            payload = _read_regular_metadata(
                layout.common_dir / filename,
                required=False,
            )
            if payload is not None:
                (safe_git_dir / filename).write_bytes(payload)
        alternates = safe_git_dir / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_bytes(layout.object_directory.as_posix().encode("utf-8") + b"\n")
        yield safe_root


def _run_git(
    repository: str | os.PathLike[str],
    args: list[str],
    *,
    check: bool = True,
    isolated_config: bool = False,
    trusted_git: _TrustedGit | None = None,
) -> subprocess.CompletedProcess[bytes]:
    git = trusted_git or _freeze_trusted_git(repository)
    repository_path = Path(repository).expanduser().resolve(strict=False)
    if isolated_config or args == ["--version"]:
        return _spawn_git(repository_path, args, git=git, check=check)
    layout = _repository_layout(repository)
    with _safe_repository_view(layout, git) as safe_root:
        return _spawn_git(
            layout.root,
            args,
            git=git,
            check=check,
            git_dir=safe_root / ".git",
            work_tree=layout.root,
        )


def repository_root(repository: str | os.PathLike[str]) -> Path:
    """Return the canonical top-level path of a non-bare Git repository."""

    return _repository_layout(repository).root


def resolve_commit(repository: str | os.PathLike[str], revision: str = "HEAD") -> str:
    """Resolve *revision* once and return a full immutable commit object ID.

    Symbolic input is accepted at this boundary for convenience.  The returned
    hexadecimal object ID, never the symbolic input, must be retained and used by
    callers as the snapshot truth.
    """

    root = repository_root(repository)
    git = _freeze_trusted_git(root)
    return _resolve_commit_with_git(root, revision, git)


def _resolve_commit_with_git(root: Path, revision: str, git: _TrustedGit) -> str:
    if not isinstance(revision, str) or not revision.strip():
        raise UsageError("Git revision must be a non-empty string.")
    revision = revision.strip()
    if revision.startswith("-") or "\x00" in revision:
        raise UsageError("Git revision is not safe to pass to Git.")

    result = _run_git(
        root,
        ["rev-parse", "--verify", f"{revision}^{{commit}}"],
        trusted_git=git,
    )
    commit = _decode(result.stdout).strip().lower()
    if not _OBJECT_ID_RE.fullmatch(commit):
        raise IntegrityError("Git returned an invalid commit object ID.", details={"value": commit})
    return commit


def _copy_regular_file(source: Path, destination: Path) -> None:
    payload = _read_regular_metadata(source, required=False)
    if payload is None:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)


def _remove_tree_without_following_links(root: Path) -> None:
    """Remove one known temporary tree without traversing reparse points."""

    try:
        root_stat = root.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if _is_reparse_point(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise IntegrityError("Temporary worktree root changed before cleanup.")

    def remove_entry(path: Path, value: os.stat_result) -> None:
        if _is_reparse_point(value):
            try:
                path.unlink()
            except (IsADirectoryError, PermissionError):
                os.rmdir(path)
            return
        if stat.S_ISDIR(value.st_mode):
            current = path.stat(follow_symlinks=False)
            if _is_reparse_point(current) or not stat.S_ISDIR(current.st_mode):
                remove_entry(path, current)
                return
            with os.scandir(path) as iterator:
                children = list(iterator)
            for child in children:
                child_path = Path(child.path)
                remove_entry(child_path, child_path.stat(follow_symlinks=False))
            os.rmdir(path)
            return
        path.unlink()

    with os.scandir(root) as iterator:
        entries = list(iterator)
    for entry in entries:
        path = Path(entry.path)
        remove_entry(path, path.stat(follow_symlinks=False))
    os.rmdir(root)


def _worktree_blob_ids(root: Path, raw_path: bytes, mode: str, object_format: str) -> set[str]:
    try:
        rendered = raw_path.decode("utf-8", errors="surrogateescape")
        pure = PurePosixPath(rendered)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != rendered:
            return set()
        path = root.joinpath(*pure.parts)
        before = path.stat(follow_symlinks=False)
        if mode == "120000" and stat.S_ISLNK(before.st_mode):
            payload = os.fsencode(os.readlink(path))
        elif mode in {"100644", "100755"} and stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mode,
                    opened.st_size,
                    opened.st_mtime_ns,
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_size,
                    before.st_mtime_ns,
                ):
                    return set()
                payload = stream.read()
                after = os.fstat(stream.fileno())
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_size,
                    after.st_mtime_ns,
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_size,
                    before.st_mtime_ns,
                ):
                    return set()
        else:
            return set()
    except OSError:
        return set()

    candidates = {payload}
    if mode in {"100644", "100755"} and b"\r\n" in payload:
        candidates.add(payload.replace(b"\r\n", b"\n"))
    object_ids: set[str] = set()
    for candidate in candidates:
        digest = hashlib.new(object_format)
        digest.update(f"blob {len(candidate)}\0".encode("ascii"))
        digest.update(candidate)
        object_ids.add(digest.hexdigest())
    return object_ids


def _discard_filter_only_status(
    root: Path,
    status: bytes,
    index: bytes,
    *,
    object_format: str,
) -> bytes:
    index_entries: dict[bytes, tuple[str, str]] = {}
    for record in index.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError):
            return status
        if stage != "0" or raw_path in index_entries:
            return status
        index_entries[raw_path] = (mode, object_id)

    retained: list[bytes] = []
    for record in status.split(b"\0"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            retained.append(record)
            continue
        index_state, worktree_state = record[:1], record[1:2]
        raw_path = record[3:]
        indexed = index_entries.get(raw_path)
        if index_state == b" " and worktree_state != b" " and indexed is not None:
            mode, object_id = indexed
            if object_id in _worktree_blob_ids(root, raw_path, mode, object_format):
                continue
        retained.append(record)
    return b"\0".join(retained) + (b"\0" if retained else b"")


def _isolated_repository_status(root: Path, *, trusted_git: _TrustedGit | None = None) -> bytes:
    """Read status through fresh Git metadata that has no executable filter config."""

    layout = _repository_layout(root)
    git = trusted_git or _freeze_trusted_git(root)
    head = _resolve_commit_with_git(root, "HEAD", git)
    source_index = layout.git_dir / "index"
    source_index_bytes = _read_regular_metadata(source_index)
    if source_index_bytes is None:
        raise IntegrityError(
            "Required Git index metadata is missing.",
            details={"path": str(source_index)},
        )

    with _safe_repository_view(layout, git) as safe_repository:
        safe_git_dir = safe_repository / ".git"
        (safe_git_dir / "index").write_bytes(source_index_bytes)
        for shared_index in source_index.parent.glob("sharedindex.*"):
            _copy_regular_file(shared_index, safe_git_dir / shared_index.name)

        for source_info in dict.fromkeys((layout.common_dir / "info", layout.git_dir / "info")):
            for name in ("attributes", "exclude", "sparse-checkout"):
                _copy_regular_file(source_info / name, safe_git_dir / "info" / name)

        status = _spawn_git(
            root,
            [
                "-c",
                f"core.autocrlf={'true' if os.name == 'nt' else 'false'}",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
                "--no-renames",
            ],
            git=git,
            check=True,
            git_dir=safe_git_dir,
            work_tree=root,
        ).stdout
        index_entries = _spawn_git(
            root,
            ["ls-files", "--stage", "-z"],
            git=git,
            check=True,
            git_dir=safe_git_dir,
            work_tree=root,
        ).stdout
        status = _discard_filter_only_status(
            root,
            status,
            index_entries,
            object_format=layout.object_format,
        )

    if (
        _read_regular_metadata(source_index) != source_index_bytes
        or _resolve_commit_with_git(root, "HEAD", git) != head
    ):
        raise IntegrityError("Repository state changed while cleanliness was being checked.")
    return status


def assert_clean_repository(repository: str | os.PathLike[str]) -> None:
    """Reject changes without loading repository-controlled executable Git config."""

    root = repository_root(repository)
    git = _freeze_trusted_git(root)
    status = _isolated_repository_status(root, trusted_git=git)
    if status:
        entries = [_decode(entry) for entry in status.split(b"\0") if entry]
        raise IntegrityError(
            "Repository must be clean before a snapshot is captured.",
            details={"repository_path": str(root), "status": entries},
        )


# A concise compatibility name for callers that phrase this as a precondition.
require_clean_repository = assert_clean_repository


def _tree_entries(
    repository: Path,
    commit: str,
    *,
    trusted_git: _TrustedGit | None = None,
) -> list[tuple[str, str, str, str]]:
    """Return sorted ``(mode, type, object_id, path)`` entries for a commit."""

    raw = _run_git(
        repository,
        ["ls-tree", "-r", "-z", commit],
        trusted_git=trusted_git,
    ).stdout
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


def _git_blob(
    repository: Path,
    object_id: str,
    *,
    trusted_git: _TrustedGit | None = None,
) -> bytes:
    return _run_git(
        repository,
        ["cat-file", "blob", object_id],
        trusted_git=trusted_git,
    ).stdout


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
    git = _freeze_trusted_git(root)
    if require_clean:
        status = _isolated_repository_status(root, trusted_git=git)
        if status:
            entries = [_decode(entry) for entry in status.split(b"\0") if entry]
            raise IntegrityError(
                "Repository must be clean before a snapshot is captured.",
                details={"repository_path": str(root), "status": entries},
            )

    commit = _resolve_commit_with_git(root, revision, git)
    tree = _decode(
        _run_git(
            root,
            ["rev-parse", f"{commit}^{{tree}}"],
            trusted_git=git,
        ).stdout
    ).strip()
    if not _OBJECT_ID_RE.fullmatch(tree):
        raise IntegrityError("Git returned an invalid tree object ID.", details={"tree": tree})

    submodules: list[dict[str, str]] = []
    dependency_locks: list[dict[str, str]] = []
    for mode, object_type, object_id, path in _tree_entries(root, commit, trusted_git=git):
        if mode == "160000" and object_type == "commit":
            submodules.append({"path": path, "commit": object_id})
        elif object_type == "blob" and _is_dependency_lock(path):
            dependency_locks.append(
                {
                    "path": path,
                    "git_blob": object_id,
                    "sha256": sha256_bytes(_git_blob(root, object_id, trusted_git=git)),
                }
            )

    git_version_result = _run_git(root, ["--version"], trusted_git=git)
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
        status = _isolated_repository_status(root, trusted_git=git)
        if status:
            raise IntegrityError("Repository state changed during snapshot capture.")
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
    git = _freeze_trusted_git(root)
    pinned_commit = _resolve_commit_with_git(root, commit, git)
    if pinned_commit != commit.lower():
        raise IntegrityError("Snapshot commit must be a full immutable object ID.")
    inventory: list[dict[str, Any]] = []
    for mode, object_type, object_id, path in _tree_entries(root, pinned_commit, trusted_git=git):
        if object_type == "blob":
            size = len(_git_blob(root, object_id, trusted_git=git))
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
    git = _freeze_trusted_git(root)
    pinned_commit = _resolve_commit_with_git(root, commit, git)
    if pinned_commit != commit.lower():
        raise IntegrityError("Snapshot commit must be a full immutable object ID.")
    for mode, object_type, object_id, entry_path in _tree_entries(
        root, pinned_commit, trusted_git=git
    ):
        if entry_path != path:
            continue
        if object_type != "blob" or mode == "160000":
            raise UsageError("Snapshot entry is not a readable file.", details={"path": path})
        return _git_blob(root, object_id, trusted_git=git)
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
    git = _freeze_trusted_git(root)
    layout = _repository_layout(root)
    if require_source_clean:
        source_status = _isolated_repository_status(root, trusted_git=git)
        if source_status:
            raise IntegrityError("Source repository must be clean for temporary replay.")
    pinned_commit = _resolve_commit_with_git(root, commit, git)

    parent_path: Path | None = None
    if parent is not None:
        parent_path = Path(parent).expanduser().resolve()
        parent_path.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(tempfile.mkdtemp(prefix="unasked-worktree-", dir=parent_path)).resolve()
    worktree = temporary_root / "checkout"
    body_error: BaseException | None = None
    try:
        worktree.mkdir(parents=True)
        empty_template = temporary_root / "empty-template"
        empty_template.mkdir()
        init_args = ["init", "--quiet", f"--template={empty_template}"]
        if layout.object_format == "sha256":
            init_args.append("--object-format=sha256")
        _run_git(
            worktree,
            init_args,
            isolated_config=True,
            trusted_git=git,
        )
        alternates = worktree / ".git" / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_bytes(layout.object_directory.as_posix().encode("utf-8") + b"\n")
        _run_git(
            worktree,
            ["config", "core.autocrlf", "false"],
            isolated_config=True,
            trusted_git=git,
        )
        _run_git(
            worktree,
            ["config", "core.fsmonitor", "false"],
            isolated_config=True,
            trusted_git=git,
        )
        _run_git(
            worktree,
            ["config", "core.hooksPath", str(temporary_root / "no-hooks")],
            isolated_config=True,
            trusted_git=git,
        )
        _run_git(
            worktree,
            ["checkout", "--detach", "--force", pinned_commit],
            isolated_config=True,
            trusted_git=git,
        )
        _run_git(
            worktree,
            ["repack", "-a", "-d", "--no-write-bitmap-index"],
            isolated_config=True,
            trusted_git=git,
        )
        for pack_file in (worktree / ".git" / "objects" / "pack").iterdir():
            pack_stat = pack_file.stat(follow_symlinks=False)
            if _is_reparse_point(pack_stat) or not stat.S_ISREG(pack_stat.st_mode):
                raise IntegrityError("Git repack produced an unsafe object database entry.")
            os.chmod(pack_file, pack_stat.st_mode | stat.S_IWUSR)
        alternates.unlink()
        actual = _decode(
            _run_git(
                worktree,
                ["rev-parse", "--verify", "HEAD^{commit}"],
                isolated_config=True,
                trusted_git=git,
            ).stdout
        ).strip()
        if actual != pinned_commit:
            raise IntegrityError(
                "Temporary worktree is not pinned to the requested commit.",
                details={"expected": pinned_commit, "actual": actual},
            )
        status = _run_git(
            worktree,
            [
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
                "--no-renames",
            ],
            isolated_config=True,
            trusted_git=git,
        ).stdout
        if status:
            raise IntegrityError("Temporary worktree was not clean after checkout.")
        yield worktree
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            _remove_tree_without_following_links(temporary_root)
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
