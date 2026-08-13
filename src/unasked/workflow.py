from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from unasked import __version__
from unasked.artifacts import ArtifactMetadata, ArtifactStore
from unasked.errors import IntegrityError, PolicyError, UnaskedError, UsageError
from unasked.executables import find_executable
from unasked.observer import observe_repository
from unasked.outcomes import classify_outcome
from unasked.policy import Actor, Capability, State, require_capability
from unasked.project import SCHEMA_VERSION, Project
from unasked.repository import temporary_worktree
from unasked.sandbox import ISOLATION_NOTICE, RestrictedExecutor
from unasked.schemas import validate_or_raise
from unasked.util import canonical_json, hash_json, read_json, sha256_bytes, sha256_file, utc_now

_SYSTEM_DIFF_COMMAND = {
    "command_id": "CMD-CAPTURE-DIFF",
    "argv": [
        "unasked-internal",
        "capture-worktree-mutations",
        "--format=canonical-json",
    ],
    "working_directory": ".",
    "purpose": "Capture every sandbox-only filesystem and Git-metadata mutation.",
    "expected_observation": "A complete canonical mutation manifest, possibly empty.",
}

_T = TypeVar("_T")


def _compound_run_mutation(method: Callable[..., _T]) -> Callable[..., _T]:
    """Hold one run lock from a service operation's first read through its final event."""

    @wraps(method)
    def wrapped(self: InvestigationService, run_id: str, *args: Any, **kwargs: Any) -> _T:
        with self.project.mutation(run_id):
            return method(self, run_id, *args, **kwargs)

    return wrapped


_ROOT_GUARD_KEY = b""
_LOCAL_ENVIRONMENT_LIMITATION = "environment-name stripping only"


@dataclass(frozen=True)
class _FilesystemEntry:
    descriptor: dict[str, Any]
    path: Path
    payload: bytes | None = None
    stat_result: os.stat_result | None = None


def _relative_path_bytes(root: Path, path: Path) -> bytes:
    return path.relative_to(root).as_posix().encode("utf-8", errors="surrogateescape")


def _entry_descriptor(relative_bytes: bytes, *, kind: str, mode: int) -> dict[str, Any]:
    return {
        "kind": kind,
        "mode": f"{mode:04o}",
        "path": relative_bytes.decode("utf-8", errors="replace"),
        "path_bytes_base64": base64.b64encode(relative_bytes).decode("ascii"),
    }


def _filesystem_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        getattr(value, "st_file_attributes", 0),
        getattr(value, "st_reparse_tag", 0),
    )


def _stable_directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        getattr(value, "st_file_attributes", 0),
        getattr(value, "st_reparse_tag", 0),
    )


def _assert_no_named_streams(path: Path) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class _StreamData(ctypes.Structure):
        _fields_ = [
            ("stream_size", ctypes.c_longlong),
            ("stream_name", wintypes.WCHAR * 296),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(_StreamData),
        wintypes.DWORD,
    ]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_StreamData)]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL

    data = _StreamData()
    handle = find_first(str(path), 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in {2, 38}:
            return
        raise IntegrityError(
            "Unable to enumerate sandbox file streams.",
            details={"path": str(path), "winerror": error},
        )
    names: list[str] = []
    try:
        while True:
            names.append(data.stream_name)
            if find_next(handle, ctypes.byref(data)):
                continue
            error = ctypes.get_last_error()
            if error == 38:
                break
            raise IntegrityError(
                "Unable to enumerate sandbox file streams.",
                details={"path": str(path), "winerror": error},
            )
    finally:
        find_close(handle)
    unexpected = [name for name in names if name.casefold() != "::$data"]
    if unexpected:
        raise IntegrityError(
            "NTFS alternate data streams are outside the mutation capture surface.",
            details={"path": str(path), "streams": unexpected},
        )


def _hash_regular_file_without_following(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IntegrityError(
            "Unable to open a sandbox file without following links.",
            details={"path": str(path), "error": str(exc)},
        ) from exc
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
            expected.st_size,
            expected.st_mtime_ns,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if expected_identity != opened_identity or not stat.S_ISREG(opened.st_mode):
            raise IntegrityError(
                "A sandbox file changed before it could be captured.",
                details={"path": str(path)},
            )
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        closed_identity = os.fstat(stream.fileno())
        if (
            closed_identity.st_dev,
            closed_identity.st_ino,
            closed_identity.st_mode,
            closed_identity.st_size,
            closed_identity.st_mtime_ns,
        ) != expected_identity:
            raise IntegrityError(
                "A sandbox file changed while it was being captured.",
                details={"path": str(path)},
            )
    return digest.hexdigest()


def _read_regular_file_without_following(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IntegrityError(
            "Unable to reopen a sandbox mutation without following links.",
            details={"path": str(path), "error": str(exc)},
        ) from exc
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
            expected.st_size,
            expected.st_mtime_ns,
        )
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
        ) != expected_identity or not stat.S_ISREG(opened.st_mode):
            raise IntegrityError(
                "A sandbox mutation changed before it could be stored.",
                details={"path": str(path)},
            )
        payload = stream.read()
        closed = os.fstat(stream.fileno())
        if (
            closed.st_dev,
            closed.st_ino,
            closed.st_mode,
            closed.st_size,
            closed.st_mtime_ns,
        ) != expected_identity:
            raise IntegrityError(
                "A sandbox mutation changed while it was being stored.",
                details={"path": str(path)},
            )
    return payload


def _scan_worktree(
    root: Path,
    *,
    expected_root_identity: tuple[int, ...] | None = None,
) -> dict[bytes, _FilesystemEntry]:
    """Hash a worktree without following symlinks, junctions, or Git configuration."""

    root = Path(os.path.abspath(os.path.expanduser(os.fspath(root))))
    try:
        root_stat = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise IntegrityError("Unable to inspect the sandbox root.") from exc
    root_identity = _stable_directory_identity(root_stat)
    root_scan_identity = _filesystem_identity(root_stat)
    is_root_reparse = bool(getattr(root_stat, "st_file_attributes", 0) & 0x400)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_ISLNK(root_stat.st_mode)
        or is_root_reparse
        or (expected_root_identity is not None and root_identity != expected_root_identity)
    ):
        raise IntegrityError("The sandbox root identity changed or became a reparse point.")
    _assert_no_named_streams(root)

    pending = [(root, root_stat)]
    discovered: dict[bytes, _FilesystemEntry] = {
        _ROOT_GUARD_KEY: _FilesystemEntry(
            {"kind": "ROOT_GUARD"},
            root,
            stat_result=root_stat,
        )
    }
    while pending:
        directory, expected_directory = pending.pop()
        try:
            current_directory = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise IntegrityError("A sandbox directory changed before enumeration.") from exc
        if _filesystem_identity(current_directory) != _filesystem_identity(expected_directory):
            raise IntegrityError("A sandbox directory changed before enumeration.")
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise IntegrityError(
                "Unable to enumerate the sandbox mutation surface.",
                details={"path": str(directory), "error": str(exc)},
            ) from exc
        for entry in entries:
            path = Path(entry.path)
            relative_bytes = _relative_path_bytes(root, path)
            try:
                before = path.stat(follow_symlinks=False)
            except OSError as exc:
                raise IntegrityError(
                    "Unable to inspect a sandbox mutation entry.",
                    details={"path": str(path), "error": str(exc)},
                ) from exc
            mode = stat.S_IMODE(before.st_mode)
            is_reparse = bool(getattr(before, "st_file_attributes", 0) & 0x400)
            if stat.S_ISLNK(before.st_mode) or is_reparse:
                try:
                    payload = os.fsencode(os.readlink(path))
                except OSError as exc:
                    raise IntegrityError(
                        "Unable to read a sandbox link without following it.",
                        details={"path": str(path), "error": str(exc)},
                    ) from exc
                after_link = path.stat(follow_symlinks=False)
                if (
                    after_link.st_dev,
                    after_link.st_ino,
                    after_link.st_mode,
                    after_link.st_size,
                    after_link.st_mtime_ns,
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_size,
                    before.st_mtime_ns,
                ):
                    raise IntegrityError(
                        "A sandbox link changed while it was being captured.",
                        details={"path": str(path)},
                    )
                descriptor = _entry_descriptor(relative_bytes, kind="SYMLINK", mode=mode)
                descriptor.update({"sha256": sha256_bytes(payload), "size_bytes": len(payload)})
                discovered[relative_bytes] = _FilesystemEntry(descriptor, path, payload)
                continue
            _assert_no_named_streams(path)
            if stat.S_ISDIR(before.st_mode):
                descriptor = _entry_descriptor(relative_bytes, kind="DIRECTORY", mode=mode)
                discovered[relative_bytes] = _FilesystemEntry(descriptor, path)
                pending.append((path, before))
                continue
            if stat.S_ISREG(before.st_mode):
                digest = _hash_regular_file_without_following(path, before)
                try:
                    after = path.stat(follow_symlinks=False)
                except OSError as exc:
                    raise IntegrityError(
                        "A sandbox file changed while it was being captured.",
                        details={"path": str(path), "error": str(exc)},
                    ) from exc
                identity_before = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_size,
                    before.st_mtime_ns,
                )
                identity_after = (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_size,
                    after.st_mtime_ns,
                )
                if identity_before != identity_after:
                    raise IntegrityError(
                        "A sandbox file changed while it was being captured.",
                        details={"path": str(path)},
                    )
                descriptor = _entry_descriptor(relative_bytes, kind="FILE", mode=mode)
                descriptor.update({"sha256": digest, "size_bytes": before.st_size})
                discovered[relative_bytes] = _FilesystemEntry(
                    descriptor,
                    path,
                    stat_result=before,
                )
                continue
            descriptor = _entry_descriptor(relative_bytes, kind="SPECIAL", mode=mode)
            discovered[relative_bytes] = _FilesystemEntry(descriptor, path)
        final_directory = directory.stat(follow_symlinks=False)
        if _filesystem_identity(final_directory) != _filesystem_identity(expected_directory):
            raise IntegrityError("A sandbox directory changed during enumeration.")
    final_root = root.stat(follow_symlinks=False)
    if _filesystem_identity(final_root) != root_scan_identity:
        raise IntegrityError("The sandbox root changed during mutation capture.")
    return discovered


def _capture_worktree_mutations(
    root: Path,
    before: dict[bytes, _FilesystemEntry],
    *,
    store: ArtifactStore,
    artifact_byte_limit: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root_guard = before.get(_ROOT_GUARD_KEY)
    if root_guard is None or root_guard.stat_result is None:
        raise IntegrityError("The mutation baseline is missing its root identity guard.")
    after = _scan_worktree(
        root,
        expected_root_identity=_stable_directory_identity(root_guard.stat_result),
    )
    changes: list[dict[str, Any]] = []
    artifact_refs: list[dict[str, Any]] = []
    artifact_bytes = 0
    complete = True
    for key in sorted((set(before) | set(after)) - {_ROOT_GUARD_KEY}):
        before_entry = before.get(key)
        after_entry = after.get(key)
        before_descriptor = before_entry.descriptor if before_entry is not None else None
        after_descriptor = after_entry.descriptor if after_entry is not None else None
        if before_descriptor == after_descriptor:
            continue
        change = {
            "change": (
                "ADDED"
                if before_entry is None
                else "DELETED"
                if after_entry is None
                else "MODIFIED"
            ),
            "before": before_descriptor,
            "after": after_descriptor,
        }
        if after_entry is not None and after_entry.descriptor["kind"] in {"FILE", "SYMLINK"}:
            size = int(after_entry.descriptor["size_bytes"])
            if artifact_bytes + size > artifact_byte_limit:
                complete = False
            else:
                if after_entry.descriptor["kind"] == "FILE":
                    if after_entry.stat_result is None:
                        raise IntegrityError("A regular mutation is missing its file identity.")
                    payload = _read_regular_file_without_following(
                        after_entry.path,
                        after_entry.stat_result,
                    )
                    metadata = store.put_bytes(
                        payload,
                        media_type="application/octet-stream",
                        original_name=after_entry.path.name,
                    )
                else:
                    metadata = store.put_bytes(
                        after_entry.payload or b"",
                        media_type="application/vnd.unasked.symlink-target",
                        original_name=f"{after_entry.path.name}.symlink-target",
                    )
                if metadata.sha256 != after_entry.descriptor["sha256"]:
                    raise IntegrityError(
                        "A sandbox mutation changed while its artifact was stored.",
                        details={"path": str(after_entry.path)},
                    )
                reference = metadata.to_reference()
                change["after_artifact"] = reference
                artifact_refs.append(reference)
                artifact_bytes += size
        changes.append(change)
    return (
        {
            "artifact_bytes": artifact_bytes,
            "capture": "authority_filesystem_manifest_v1",
            "change_count": len(changes),
            "changes": changes,
            "complete": complete,
            "reason_codes": [] if complete else ["CAPTURE_ARTIFACT_LIMIT_EXCEEDED"],
            "scope": "worktree_and_git_metadata",
        },
        artifact_refs,
    )


def _read_bound_cas_reference(
    store: ArtifactStore,
    reference: Any,
    *,
    schema_name: str | None = None,
) -> tuple[ArtifactMetadata, bytes] | None:
    """Read a fully bound CAS reference, returning ``None`` on any mismatch."""

    if not isinstance(reference, dict):
        return None
    try:
        digest = reference["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return None
        verification = store.verify(digest)
        metadata = verification.metadata
        if not verification.valid or metadata is None:
            return None
        expected = metadata.to_reference(schema_name=schema_name)
        if reference != expected:
            return None
        payload = verification.path.read_bytes()
        if len(payload) != metadata.size or sha256_bytes(payload) != digest:
            return None
        return metadata, payload
    except Exception:
        return None


def _valid_capture_descriptor(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    expected_keys = {"kind", "mode", "path", "path_bytes_base64"}
    if kind in {"FILE", "SYMLINK"}:
        expected_keys.update({"sha256", "size_bytes"})
    elif kind not in {"DIRECTORY", "SPECIAL"}:
        return False
    if set(value) != expected_keys:
        return False
    mode = value.get("mode")
    if (
        not isinstance(mode, str)
        or len(mode) != 4
        or any(character not in "01234567" for character in mode)
    ):
        return False
    path = value.get("path")
    encoded_path = value.get("path_bytes_base64")
    if not isinstance(path, str) or not path or not isinstance(encoded_path, str):
        return False
    try:
        path_bytes = base64.b64decode(encoded_path, validate=True)
    except (ValueError, TypeError):
        return False
    if (
        not path_bytes
        or b"\x00" in path_bytes
        or path_bytes.startswith(b"/")
        or any(part in {b"", b".", b".."} for part in path_bytes.split(b"/"))
        or base64.b64encode(path_bytes).decode("ascii") != encoded_path
        or path_bytes.decode("utf-8", errors="replace") != path
    ):
        return False
    if kind in {"FILE", "SYMLINK"}:
        digest = value.get("sha256")
        size = value.get("size_bytes")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            return False
    return True


def _valid_complete_capture_manifest(
    manifest: Any,
    *,
    store: ArtifactStore,
    artifact_byte_limit: int,
) -> tuple[bool, list[dict[str, Any]]]:
    expected_keys = {
        "artifact_bytes",
        "capture",
        "change_count",
        "changes",
        "complete",
        "reason_codes",
        "scope",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        return False, []
    artifact_bytes = manifest.get("artifact_bytes")
    change_count = manifest.get("change_count")
    changes = manifest.get("changes")
    if (
        manifest.get("capture") != "authority_filesystem_manifest_v1"
        or manifest.get("scope") != "worktree_and_git_metadata"
        or manifest.get("complete") is not True
        or manifest.get("reason_codes") != []
        or isinstance(artifact_bytes, bool)
        or not isinstance(artifact_bytes, int)
        or artifact_bytes < 0
        or artifact_bytes > artifact_byte_limit
        or isinstance(change_count, bool)
        or not isinstance(change_count, int)
        or not isinstance(changes, list)
        or change_count != len(changes)
    ):
        return False, []

    artifact_refs: list[dict[str, Any]] = []
    captured_bytes = 0
    changed_paths: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            return False, []
        allowed_keys = {"change", "before", "after", "after_artifact"}
        if not {"change", "before", "after"}.issubset(change) or not set(change) <= allowed_keys:
            return False, []
        before = change["before"]
        after = change["after"]
        if before is not None and not _valid_capture_descriptor(before):
            return False, []
        if after is not None and not _valid_capture_descriptor(after):
            return False, []
        if before is None and after is not None:
            expected_change = "ADDED"
        elif before is not None and after is None:
            expected_change = "DELETED"
        elif before is not None and after is not None and before != after:
            expected_change = "MODIFIED"
        else:
            return False, []
        if change.get("change") != expected_change:
            return False, []
        descriptor = after if after is not None else before
        if not isinstance(descriptor, dict):
            return False, []
        path_key = descriptor["path_bytes_base64"]
        if path_key in changed_paths:
            return False, []
        changed_paths.add(path_key)
        if (
            before is not None
            and after is not None
            and before["path_bytes_base64"] != after["path_bytes_base64"]
        ):
            return False, []

        needs_artifact = after is not None and after["kind"] in {"FILE", "SYMLINK"}
        if needs_artifact:
            reference = change.get("after_artifact")
            bound = _read_bound_cas_reference(store, reference)
            if bound is None:
                return False, []
            metadata, _ = bound
            if metadata.sha256 != after["sha256"] or metadata.size != after["size_bytes"]:
                return False, []
            artifact_refs.append(reference)
            captured_bytes += metadata.size
        elif "after_artifact" in change:
            return False, []
    return captured_bytes == artifact_bytes, artifact_refs


def capture_executions_complete(
    executions: Any,
    *,
    store: ArtifactStore,
    artifact_byte_limit: int,
) -> bool:
    """Fail closed unless executions end in one authentic, complete mutation capture."""

    try:
        if (
            isinstance(artifact_byte_limit, bool)
            or not isinstance(artifact_byte_limit, int)
            or artifact_byte_limit < 0
            or not isinstance(executions, list)
            or not executions
        ):
            return False
        command_ids = [
            execution.get("command_id") if isinstance(execution, dict) else None
            for execution in executions
        ]
        if (
            any(not isinstance(command_id, str) for command_id in command_ids)
            or len(command_ids) != len(set(command_ids))
            or command_ids.count("CMD-CAPTURE-DIFF") != 1
            or command_ids[-1] != "CMD-CAPTURE-DIFF"
        ):
            return False
        capture = executions[-1]
        if set(capture) != {
            "command_id",
            "started_at",
            "completed_at",
            "exit_code",
            "stdout_ref",
            "stderr_ref",
            "diff_ref",
            "artifact_refs",
        }:
            return False
        if (
            isinstance(capture.get("exit_code"), bool)
            or capture.get("exit_code") != 0
            or not isinstance(capture.get("started_at"), str)
            or not capture.get("started_at")
            or not isinstance(capture.get("completed_at"), str)
            or not capture.get("completed_at")
            or capture.get("diff_ref") != capture.get("stdout_ref")
        ):
            return False

        stdout_bound = _read_bound_cas_reference(store, capture.get("stdout_ref"))
        stderr_bound = _read_bound_cas_reference(store, capture.get("stderr_ref"))
        if stdout_bound is None or stderr_bound is None:
            return False
        _, stdout = stdout_bound
        _, stderr = stderr_bound
        if stderr != b"":
            return False
        try:
            manifest = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if stdout != canonical_json(manifest):
            return False
        manifest_valid, mutation_refs = _valid_complete_capture_manifest(
            manifest,
            store=store,
            artifact_byte_limit=artifact_byte_limit,
        )
        if not manifest_valid:
            return False

        artifact_refs = capture.get("artifact_refs")
        if not isinstance(artifact_refs, list) or not artifact_refs:
            return False
        record_bound = _read_bound_cas_reference(
            store,
            artifact_refs[0],
            schema_name="execution-record",
        )
        if record_bound is None or artifact_refs[1:] != mutation_refs:
            return False
        _, record_payload = record_bound
        try:
            execution_record = json.loads(record_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if record_payload != canonical_json(execution_record):
            return False
        return execution_record == {
            "argv": list(_SYSTEM_DIFF_COMMAND["argv"]),
            "completed_at": capture["completed_at"],
            "cwd": ".",
            "exit_code": 0,
            "expected_observation": _SYSTEM_DIFF_COMMAND["expected_observation"],
            "isolation": "internal_authority_capture",
            "network_isolated": False,
            "purpose": _SYSTEM_DIFF_COMMAND["purpose"],
            "resolved_executable": "unasked-internal",
            "started_at": capture["started_at"],
            "stderr": "",
            "stdout": stdout.decode("utf-8"),
            "timed_out": False,
        }
    except Exception:
        return False


def _executable_basename(value: str) -> str:
    name = Path(value.replace("\\", "/")).name.casefold()
    # Win32 normalizes trailing spaces/dots and accepts NTFS alternate-data-stream
    # syntax.  Normalize those spellings even on non-Windows test hosts so a
    # model cannot disguise the Git executable from the planning gate.
    name = name.rstrip(" .")
    if ":" in name:
        name = name.split(":", 1)[0].rstrip(" .")
    for suffix in (".exe", ".com"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _reject_model_git_command(
    command: dict[str, Any],
    *,
    resolved_executable: Path | None = None,
    trusted_git: Path | None = None,
) -> None:
    argv = command.get("argv")
    candidates = []
    if isinstance(argv, list) and argv and isinstance(argv[0], str):
        candidates.append(argv[0])
    if resolved_executable is not None:
        candidates.append(str(resolved_executable))
    same_as_trusted_git = False
    if resolved_executable is not None and trusted_git is not None:
        try:
            same_as_trusted_git = os.path.samefile(resolved_executable, trusted_git)
        except OSError:
            same_as_trusted_git = False
    if same_as_trusted_git or any(
        _executable_basename(candidate) == "git" for candidate in candidates
    ):
        raise PolicyError(
            "Model-authored Git commands are not accepted; Git is reserved for the "
            "system-generated, exact diff capture command."
        )


def _normalize_experiment_commands(commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(commands, list) or any(not isinstance(item, dict) for item in commands):
        raise UsageError("Experiment commands must be an array of command objects.")
    supplied_command_ids = [command.get("command_id") for command in commands]
    if any(
        not isinstance(command_id, str) or not command_id for command_id in supplied_command_ids
    ):
        raise UsageError("Every experiment command requires a non-empty string command_id.")
    if "CMD-CAPTURE-DIFF" in supplied_command_ids:
        raise PolicyError("CMD-CAPTURE-DIFF is reserved for the authority-controlled system.")
    if len(supplied_command_ids) != len(set(supplied_command_ids)):
        raise UsageError("Experiment command IDs must be unique.")
    for command in commands:
        _reject_model_git_command(command)
    normalized_commands = copy.deepcopy(commands)
    normalized_commands.append(copy.deepcopy(_SYSTEM_DIFF_COMMAND))
    return normalized_commands


def _source_type(raw_kind: str, path: str) -> str:
    if raw_kind == "documentation_claim_source":
        return "DOCUMENTATION"
    if raw_kind == "test_path":
        return "TEST"
    if "/.github/workflows/" in f"/{path}" or raw_kind.startswith("ci_"):
        return "CI_METADATA"
    return "SOURCE"


def _observation_kind(raw_kind: str, fact: dict[str, Any]) -> str:
    if raw_kind == "documentation_claim_source":
        return "CLAIM"
    if raw_kind == "test_path":
        return "TEST_PATH"
    if raw_kind.startswith("ci_"):
        return "WORKFLOW"
    if raw_kind == "control_signal" and fact.get("category") in {
        "skip",
        "suppression",
        "continue_on_error",
    }:
        return "SUPPRESSION"
    return "STRUCTURE"


def _deduplicate_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for reference in refs:
        unique[(reference["artifact_id"], reference["sha256"])] = reference
    return [unique[key] for key in sorted(unique)]


@dataclass
class InvestigationService:
    project: Project

    @property
    def store(self) -> ArtifactStore:
        return ArtifactStore(self.project.artifacts_root)

    @_compound_run_mutation
    def observe(self, run_id: str, *, actor: Actor) -> dict[str, Any]:
        require_capability(actor, Capability.OBSERVE)
        target = self.project.get_target(run_id)
        scan_path = self.project.paths(run_id).root / "knowledge-scan.json"
        if scan_path.exists():
            raise PolicyError("The frozen repository knowledge scan is already complete.")
        raw = observe_repository(target["repository_path"], target)
        raw_meta = self.store.put_bytes(
            canonical_json(raw),
            media_type="application/json",
            original_name=f"{run_id}-raw-observations.json",
        )
        normalized: list[dict[str, Any]] = []
        for item in raw:
            source = item["source"]
            record = {
                "schema_version": SCHEMA_VERSION,
                "observation_id": item["observation_id"],
                "run_id": run_id,
                "observed_at": item["captured_at"],
                "kind": _observation_kind(item["kind"], item["fact"]),
                "statement": json.dumps(
                    item["fact"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                "source": {
                    "source_type": _source_type(item["kind"], source["path"]),
                    "path": source["path"],
                    "locator": f"L{source['line_start']}-L{source['line_end']}",
                    "sha256": source["sha256"],
                    "snapshot_hash": target["snapshot_hash"],
                },
                "acquisition": {
                    "method": "PARSE",
                    "actor_id": actor.actor_id,
                    "tool": {"name": "unasked-observer", "version": __version__},
                },
                "integrity": {
                    "status": "COMPLETE",
                    "content_hash": source["sha256"],
                    "notes": "Fact extracted without discovery interpretation.",
                },
                "snapshot_hash": target["snapshot_hash"],
            }
            enriched = self.project.append_record(
                run_id,
                collection="observations",
                schema_name="observation",
                record=record,
                actor=actor,
                event_type="OBSERVATION_RECORDED",
            )
            normalized.append(enriched)
        self.project.append_event(
            run_id,
            "OBSERVATION_BATCH_CAPTURED",
            {"count": len(normalized), "raw_sha256": raw_meta.sha256},
            actor=actor.to_dict(),
            artifact_refs=[raw_meta.to_reference()],
        )
        run = self.project.get_run(run_id)
        boundary = read_json(self.project.paths(run_id).knowledge_boundary)
        sources_by_hash = {hash_json(record["source"]): record["source"] for record in normalized}
        knowledge_scan = {
            "schema_version": SCHEMA_VERSION,
            "scan_id": f"KS-{run_id[4:]}",
            "run_id": run_id,
            "completed_at": utc_now(),
            "status": "COMPLETE",
            "knowledge_boundary_hash": run["knowledge_boundary_hash"],
            "target_snapshot_hash": target["snapshot_hash"],
            "categories": boundary["categories"],
            "source_manifest": [sources_by_hash[digest] for digest in sorted(sources_by_hash)],
            "raw_observations_ref": raw_meta.to_reference(),
            "evidence_hashes": [raw_meta.sha256],
            "scope_attestation": {
                "repository_snapshot_fully_scanned": True,
                "supplied_external_sources_fully_scanned": True,
                "omitted_sources": [],
            },
            "scanner": actor.to_dict(),
        }
        self.project.write_run_artifact(
            run_id,
            "knowledge-scan.json",
            knowledge_scan,
            actor=actor,
            event_type="KNOWLEDGE_SCAN_COMPLETED",
            schema_name="knowledge-scan",
        )
        return {
            "run_id": run_id,
            "observations": len(normalized),
            "raw_artifact": raw_meta.to_reference(),
            "knowledge_scan": knowledge_scan,
        }

    @_compound_run_mutation
    def record_custody_attestation(
        self,
        run_id: str,
        *,
        actor: Actor,
        sealed_manifest_hash: str,
        access_log_hash: str,
        sealed_at: str,
        external_store_reference: str,
    ) -> dict[str, Any]:
        if actor.role.casefold() not in {"principal_investigator", "human_judge"}:
            raise PolicyError("Only an external custodian role may attest benchmark custody.")
        for field, value in {
            "sealed_manifest_hash": sealed_manifest_hash,
            "access_log_hash": access_log_hash,
        }.items():
            try:
                valid = (
                    len(value) == 64 and value == value.lower() and len(bytes.fromhex(value)) == 32
                )
            except ValueError:
                valid = False
            if not valid:
                raise UsageError(f"{field} must be a lowercase SHA-256 digest.")
        run = self.project.get_run(run_id)
        try:
            sealed_time = datetime.fromisoformat(sealed_at.replace("Z", "+00:00"))
            run_time = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise UsageError("sealed_at must be an ISO-8601 timestamp.") from exc
        if sealed_time > run_time:
            raise PolicyError("Benchmark custody must be sealed before the investigation run.")
        attestation = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "recorded_at": utc_now(),
            "sealed_at": sealed_at,
            "sealed_manifest_hash": sealed_manifest_hash,
            "access_log_hash": access_log_hash,
            "external_store_reference": external_store_reference,
            "custodian": actor.to_dict(),
            "sealed_before_explorer": True,
            "explorer_ground_truth_access": False,
            "directional_steering": False,
            "attestation_method": "external operator declaration",
        }
        self.project.write_run_artifact(
            run_id,
            "custody-attestation.json",
            attestation,
            actor=actor,
            event_type="BENCHMARK_CUSTODY_ATTESTED",
        )
        return attestation

    @_compound_run_mutation
    def add_expectation(
        self,
        run_id: str,
        *,
        actor: Actor,
        expectation_type: str,
        statement: str,
        reasoning_chain: list[str],
        source_observation_ids: list[str],
        strength: str,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.PROPOSE_CANDIDATE)
        target = self.project.get_target(run_id)
        observations = {
            record["observation_id"]: record
            for record in self.project.records(run_id, "observations")
        }
        missing = sorted(set(source_observation_ids) - observations.keys())
        if missing:
            raise UsageError(
                "Expectation references unknown observations.", details={"missing": missing}
            )
        sources = [
            {key: value for key, value in observations[item]["source"].items()}
            for item in source_observation_ids
        ]
        expectation_id = self.project.next_id(run_id, "E", collection="expectations")
        record = {
            "schema_version": SCHEMA_VERSION,
            "expectation_id": expectation_id,
            "run_id": run_id,
            "created_at": utc_now(),
            "expectation_type": expectation_type.upper(),
            "statement": statement,
            "sources": sources,
            "reasoning_chain": reasoning_chain,
            "strength": strength.upper(),
            "snapshot_hash": target["snapshot_hash"],
        }
        return self.project.append_record(
            run_id,
            collection="expectations",
            schema_name="expectation",
            record=record,
            actor=actor,
            event_type="EXPECTATION_RECORDED",
        )

    @_compound_run_mutation
    def propose_candidate(
        self,
        run_id: str,
        *,
        actor: Actor,
        expectation_ids: list[str],
        observation_ids: list[str],
        discrepancy: str,
        materiality_question: str,
        origin: str,
        main_hypothesis: str,
        benign_alternatives: list[str],
        falsification_conditions: list[str],
        minimal_experiment: str,
        supporting_outcomes: list[str],
        falsifying_outcomes: list[str],
        inconclusive_outcomes: list[str],
        estimated_seconds: int,
        risk_level: str,
        risks: list[str],
        human_direction_provided: bool = False,
    ) -> dict[str, Any]:
        target = self.project.get_target(run_id)
        run = self.project.get_run(run_id)
        known_expectations = {
            record["expectation_id"] for record in self.project.records(run_id, "expectations")
        }
        known_observations = {
            record["observation_id"] for record in self.project.records(run_id, "observations")
        }
        missing_expectations = sorted(set(expectation_ids) - known_expectations)
        missing_observations = sorted(set(observation_ids) - known_observations)
        if missing_expectations or missing_observations:
            raise UsageError(
                "Candidate references unknown source records.",
                details={
                    "missing_expectations": missing_expectations,
                    "missing_observations": missing_observations,
                },
            )
        candidate_id = self.project.next_id(run_id, "D", collection="discoveries")
        created_at = utc_now()
        context = read_json(self.project.paths(run_id).context)
        candidate = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": candidate_id,
            "run_id": run_id,
            "created_at": created_at,
            "state": "CANDIDATE",
            "expectation_ids": expectation_ids,
            "observation_ids": observation_ids,
            "discrepancy": discrepancy,
            "materiality_question": materiality_question,
            "origin": origin.upper(),
            "provenance": {
                "prompt_hash": context["prompt_hash"],
                "context_manifest_hash": run["context_manifest_hash"],
                "human_direction_provided": human_direction_provided,
            },
            "proposed_by": actor.to_dict(),
            "snapshot_hash": target["snapshot_hash"],
        }
        hypothesis = {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": f"H-{candidate_id[2:]}",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "created_at": created_at,
            "state": "HYPOTHESIZED",
            "main_hypothesis": main_hypothesis,
            "benign_alternatives": benign_alternatives,
            "falsification_conditions": falsification_conditions,
            "minimal_experiment": minimal_experiment,
            "expected_observations": {
                "supporting": supporting_outcomes,
                "falsifying": falsifying_outcomes,
                "inconclusive": inconclusive_outcomes,
            },
            "cost_and_risk": {
                "estimated_seconds": estimated_seconds,
                "risk_level": risk_level.upper(),
                "risks": risks,
            },
            "required_capabilities": ["EXECUTE_SANDBOX"],
            "proposed_by": actor.to_dict(),
            "snapshot_hash": target["snapshot_hash"],
        }
        return self.project.create_candidate(
            run_id, candidate=candidate, hypothesis=hypothesis, actor=actor
        )

    @_compound_run_mutation
    def plan_experiment(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        commands: list[dict[str, Any]],
        support_criteria: list[str],
        falsify_criteria: list[str],
        inconclusive_criteria: list[str],
        outcome_assertions: list[dict[str, Any]],
        wall_seconds: int,
        cpu_seconds: int,
        disk_bytes: int,
        processes: int,
        mutation_scope: str = "SANDBOX_ONLY",
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REQUEST_EXPERIMENT)
        if self.project.current_state(run_id, candidate_id) is not State.HYPOTHESIZED:
            raise PolicyError("Experiment planning requires HYPOTHESIZED state.")
        bundle = self.project.read_candidate(run_id, candidate_id)
        run = self.project.get_run(run_id)
        target = self.project.get_target(run_id)
        normalized_commands = _normalize_experiment_commands(commands)
        command_ids = {command.get("command_id") for command in normalized_commands}
        assertion_ids = [assertion.get("assertion_id") for assertion in outcome_assertions]
        classifications = {assertion.get("classification") for assertion in outcome_assertions}
        if (
            len(assertion_ids) != len(set(assertion_ids))
            or classifications != {"SUPPORTS", "FALSIFIES"}
            or any(
                assertion.get("command_id") not in command_ids for assertion in outcome_assertions
            )
        ):
            raise UsageError(
                "Outcome assertions require unique IDs, both classifications, and known commands."
            )
        for assertion in outcome_assertions:
            expected = assertion.get("expected")
            if assertion.get("field") == "EXIT_CODE":
                valid_expected = isinstance(expected, int) and not isinstance(expected, bool)
            else:
                valid_expected = (
                    isinstance(expected, str)
                    and len(expected) == 64
                    and expected == expected.lower()
                    and all(character in "0123456789abcdef" for character in expected)
                )
            if not valid_expected:
                raise UsageError("Outcome assertion expected value has the wrong type or digest.")
        plan = {
            "schema_version": SCHEMA_VERSION,
            "plan_id": f"P-{candidate_id[2:]}",
            "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
            "run_id": run_id,
            "created_at": utc_now(),
            "protocol_hash": run["protocol"]["sha256"],
            "snapshot_hash": target["snapshot_hash"],
            "isolation": {
                "worktree": "ISOLATED",
                "network": "DISABLED",
                "mutation_scope": mutation_scope.upper(),
                "limits": {
                    "cpu_seconds": cpu_seconds,
                    "wall_seconds": wall_seconds,
                    "disk_bytes": disk_bytes,
                    "processes": processes,
                },
            },
            "commands": normalized_commands,
            "outcome_criteria": {
                "support": support_criteria,
                "falsify": falsify_criteria,
                "inconclusive": inconclusive_criteria,
            },
            "outcome_assertions": outcome_assertions,
            "required_capabilities": ["EXECUTE_SANDBOX"],
            "planner": actor.to_dict(),
        }
        # This is an evidence assertion, not a credential value.
        plan["isolation"]["secret_free"] = True
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/plan.json",
            plan,
            actor=actor,
            event_type="EXPERIMENT_PLANNED",
            schema_name="experiment-plan",
        )
        self.project.transition_candidate(
            run_id,
            candidate_id,
            State.TESTABLE,
            actor=actor,
            reason="A predeclared falsifiable experiment plan was frozen.",
        )
        return plan

    def _store_execution(
        self,
        *,
        run_id: str,
        target_hash: str,
        command_id: str,
        execution: dict[str, Any],
        actor: Actor,
        evidence_counter: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        stdout_meta = self.store.put_bytes(
            execution["stdout"].encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            original_name=f"{command_id}.stdout.txt",
        )
        stderr_meta = self.store.put_bytes(
            execution["stderr"].encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            original_name=f"{command_id}.stderr.txt",
        )
        record_meta = self.store.put_bytes(
            canonical_json(execution),
            media_type="application/json",
            original_name=f"{command_id}.execution.json",
        )
        common_refs = [
            stdout_meta.to_reference(),
            stderr_meta.to_reference(),
            record_meta.to_reference(schema_name="execution-record"),
        ]
        full_refs: list[dict[str, Any]] = []
        for offset, (kind, metadata) in enumerate(
            (("STDOUT", stdout_meta), ("STDERR", stderr_meta), ("COMMAND", record_meta))
        ):
            reference = {
                "schema_version": SCHEMA_VERSION,
                "evidence_id": f"EV-{evidence_counter + offset:08d}",
                "run_id": run_id,
                "kind": kind,
                "sha256": metadata.sha256,
                "uri": metadata.uri,
                "size_bytes": metadata.size,
                "media_type": metadata.media_type,
                "created_at": metadata.created_at,
                "producer": actor.to_dict(),
                "provenance": {
                    "immutable": True,
                    "target_snapshot_hash": target_hash,
                    "command_id": command_id,
                },
            }
            validate_or_raise("evidence-reference", reference)
            full_refs.append(reference)
        result_execution = {
            "command_id": command_id,
            "started_at": execution["started_at"],
            "completed_at": execution["completed_at"],
            "exit_code": execution["exit_code"] if execution["exit_code"] is not None else -1,
            "stdout_ref": stdout_meta.to_reference(),
            "stderr_ref": stderr_meta.to_reference(),
            "artifact_refs": [record_meta.to_reference(schema_name="execution-record")],
        }
        if command_id == "CMD-CAPTURE-DIFF":
            result_execution["diff_ref"] = stdout_meta.to_reference()
        return result_execution, common_refs, full_refs

    def _execute_plan(
        self,
        *,
        run_id: str,
        candidate_id: str,
        actor: Actor,
        allowed_executables: list[str],
        replay: bool,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], str]:
        root = self.project.candidate_dir(run_id, candidate_id)
        plan = read_json(root / "experiment" / "plan.json")
        target = self.project.get_target(run_id)
        all_refs: list[dict[str, Any]] = []
        result_executions: list[dict[str, Any]] = []
        evidence_records: list[dict[str, Any]] = []
        denied: str | None = None
        environment = {
            "adapter": "local_restricted",
            "fresh_git_worktree": True,
            "network_isolated": False,
            "limits_enforced": {
                "wall_seconds": True,
                "cpu_seconds": False,
                "disk_bytes": False,
                "processes": False,
            },
            "platform": platform.platform(),
            "notice": ISOLATION_NOTICE,
            "input_manifest": {
                "target_snapshot_hash": target["snapshot_hash"],
                "plan_hash": hash_json(plan),
                "allowed_executables": sorted(set(allowed_executables)),
                "system_commands": [
                    {
                        "command_id": _SYSTEM_DIFF_COMMAND["command_id"],
                        "argv": list(_SYSTEM_DIFF_COMMAND["argv"]),
                    }
                ],
            },
        }
        # This describes a documented limitation; it is not a credential value.
        environment["secret_isolation"] = _LOCAL_ENVIRONMENT_LIMITATION
        with temporary_worktree(
            target["repository_path"],
            target["commit"],
            require_source_clean=False,
        ) as worktree:
            executor = RestrictedExecutor(
                worktree,
                allowed_executables=allowed_executables,
                timeout_seconds=plan["isolation"]["limits"]["wall_seconds"],
            )
            git_path = find_executable(
                "git",
                path=os.environ.get("PATH"),
                excluded_roots=(
                    worktree,
                    Path(target["repository_path"]).resolve(),
                    Path.cwd().resolve(),
                ),
                windows_suffixes=(".exe",),
            )
            if git_path is None:
                raise PolicyError("Trusted Git executable was not found for diff capture.")
            capture_commands = [
                command
                for command in plan["commands"]
                if command.get("command_id") == "CMD-CAPTURE-DIFF"
            ]
            if (
                len(capture_commands) != 1
                or plan["commands"][-1] != capture_commands[0]
                or capture_commands[0] != _SYSTEM_DIFF_COMMAND
            ):
                raise PolicyError("The authority-controlled diff capture command was modified.")

            mutation_baseline = _scan_worktree(worktree)
            model_commands = plan["commands"][:-1]
            for index, command in enumerate(model_commands, start=1):
                started_at = utc_now()
                try:
                    resolved_executable = executor.resolve_executable(command["argv"][0])
                    _reject_model_git_command(
                        command,
                        resolved_executable=resolved_executable,
                        trusted_git=git_path,
                    )
                    execution = executor.execute(
                        command["argv"],
                        cwd=command.get("working_directory", "."),
                    )
                except UnaskedError as exc:
                    denied = f"{exc.code}: {exc.message}"
                    execution = {
                        "argv": command["argv"],
                        "cwd": command.get("working_directory", "."),
                        "stdout": "",
                        "stderr": denied,
                        "exit_code": -1,
                        "timed_out": False,
                        "isolation": "local_restricted",
                        "network_isolated": False,
                    }
                execution["started_at"] = started_at
                execution["completed_at"] = utc_now()
                execution["purpose"] = command["purpose"]
                execution["expected_observation"] = command["expected_observation"]
                result_execution, refs, full_refs = self._store_execution(
                    run_id=run_id,
                    target_hash=target["snapshot_hash"],
                    command_id=command["command_id"],
                    execution=execution,
                    actor=actor,
                    evidence_counter=(index - 1) * 3 + (100000 if replay else 0),
                )
                result_executions.append(result_execution)
                all_refs.extend(refs)
                evidence_records.extend(full_refs)
                if denied is not None:
                    break

            diff_started_at = utc_now()
            capture_error = ""
            try:
                mutation_manifest, mutation_artifact_refs = _capture_worktree_mutations(
                    worktree,
                    mutation_baseline,
                    store=self.store,
                    artifact_byte_limit=plan["isolation"]["limits"]["disk_bytes"],
                )
            except IntegrityError as exc:
                capture_error = f"{exc.code}: {exc.message}"
                denied = denied or capture_error
                mutation_manifest = {
                    "artifact_bytes": 0,
                    "capture": "authority_filesystem_manifest_v1",
                    "change_count": 0,
                    "changes": [],
                    "complete": False,
                    "reason_codes": ["CAPTURE_INTEGRITY_FAILURE"],
                    "scope": "worktree_and_git_metadata",
                }
                mutation_artifact_refs = []
            diff_execution = {
                "argv": list(_SYSTEM_DIFF_COMMAND["argv"]),
                "completed_at": utc_now(),
                "cwd": ".",
                "exit_code": 0 if mutation_manifest["complete"] else 1,
                "expected_observation": _SYSTEM_DIFF_COMMAND["expected_observation"],
                "isolation": "internal_authority_capture",
                "network_isolated": False,
                "purpose": _SYSTEM_DIFF_COMMAND["purpose"],
                "resolved_executable": "unasked-internal",
                "started_at": diff_started_at,
                "stderr": (
                    ""
                    if mutation_manifest["complete"]
                    else capture_error
                    or "Mutation artifact capture exceeded the frozen disk byte limit."
                ),
                "stdout": canonical_json(mutation_manifest).decode("utf-8"),
                "timed_out": False,
            }
            diff_index = len(model_commands) + 1
            result_execution, refs, full_refs = self._store_execution(
                run_id=run_id,
                target_hash=target["snapshot_hash"],
                command_id="CMD-CAPTURE-DIFF",
                execution=diff_execution,
                actor=actor,
                evidence_counter=(diff_index - 1) * 3 + (100000 if replay else 0),
            )
            result_execution["artifact_refs"].extend(mutation_artifact_refs)
            result_executions.append(result_execution)
            all_refs.extend([*refs, *mutation_artifact_refs])
            evidence_records.extend(full_refs)
        return result_executions, _deduplicate_refs(all_refs), environment, denied or ""

    @_compound_run_mutation
    def execute_experiment(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        allowed_executables: list[str],
    ) -> dict[str, Any]:
        require_capability(actor, Capability.EXECUTE_SANDBOX)
        if self.project.current_state(run_id, candidate_id) is not State.TESTABLE:
            raise PolicyError("Experiment execution requires TESTABLE state.")
        root = self.project.candidate_dir(run_id, candidate_id)
        plan = read_json(root / "experiment" / "plan.json")
        started_at = utc_now()
        executions, refs, environment, denied = self._execute_plan(
            run_id=run_id,
            candidate_id=candidate_id,
            actor=actor,
            allowed_executables=allowed_executables,
            replay=False,
        )
        any_timeout = any(execution["exit_code"] == -1 for execution in executions) and not denied
        any_failed = any(execution["exit_code"] != 0 for execution in executions)
        if denied:
            status = "DENIED"
        elif any_timeout:
            status = "TIMED_OUT"
        elif any_failed:
            status = "FAILED"
        else:
            status = "SUCCEEDED"
        result = {
            "schema_version": SCHEMA_VERSION,
            "result_id": f"R-{candidate_id[2:]}",
            "plan_id": plan["plan_id"],
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": utc_now(),
            "status": status,
            "observed_outcome": classify_outcome(plan["outcome_assertions"], executions),
            "environment_hash": hash_json(environment),
            "executions": executions,
            "evidence_refs": refs,
            "executor": actor.to_dict(),
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/environment.json",
            environment,
            actor=actor,
            event_type="EXECUTION_ENVIRONMENT_RECORDED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "experiment/result.json",
            result,
            actor=actor,
            event_type="EXPERIMENT_EXECUTED",
            schema_name="experiment-result",
        )
        for execution in executions:
            self.project.append_candidate_record(
                run_id,
                candidate_id,
                "experiment/commands.jsonl",
                execution,
                actor=actor,
                event_type="COMMAND_RESULT_RECORDED",
            )
        return result

    @_compound_run_mutation
    def add_review(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        review_type: str,
        conclusion: str,
        findings: list[str],
        evidence_hashes: list[str],
        tested_alternatives: list[str] | None = None,
        negative_control: str | None = None,
        semantic_variant: str | None = None,
        completeness_check: str | None = None,
        challenge_attempts: list[dict[str, Any]] | None = None,
        decision_impact: str | None = None,
    ) -> dict[str, Any]:
        normalized_type = review_type.upper()
        if normalized_type == "COUNTEREVIDENCE":
            require_capability(actor, Capability.CHALLENGE)
        elif normalized_type in {"NOVELTY", "MATERIALITY", "KNOWN_ISSUE"}:
            require_capability(actor, Capability.AUTHORIZE_VERDICT)
        else:
            raise UsageError("Unknown review type.", details={"review_type": review_type})
        review = {
            "schema_version": SCHEMA_VERSION,
            "review_id": f"REV-{normalized_type}-{candidate_id[2:]}",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "review_type": normalized_type,
            "reviewed_at": utc_now(),
            "reviewer": actor.to_dict(),
            "conclusion": conclusion.upper(),
            "findings": findings,
            "evidence_hashes": evidence_hashes,
        }
        if normalized_type == "COUNTEREVIDENCE":
            review.update(
                {
                    "tested_alternatives": tested_alternatives or [],
                    "negative_control": negative_control or "",
                    "semantic_variant": semantic_variant or "",
                    "completeness_check": completeness_check or "",
                    "challenge_attempts": challenge_attempts or [],
                }
            )
            for attempt in challenge_attempts or []:
                reference = attempt.get("result_ref", {})
                digest = reference.get("sha256", "")
                if (
                    reference.get("artifact_id") != f"sha256:{digest}"
                    or reference.get("uri") not in {None, f"cas://sha256/{digest}"}
                    or digest not in evidence_hashes
                ):
                    raise PolicyError(
                        "Challenge attempt references are not bound to evidence_hashes."
                    )
                self.store.verify_or_raise(digest)
        if normalized_type in {"NOVELTY", "KNOWN_ISSUE"}:
            review["knowledge_boundary_hash"] = self.project.get_run(run_id)[
                "knowledge_boundary_hash"
            ]
        if normalized_type == "MATERIALITY":
            review["decision_impact"] = decision_impact or ""
        validate_or_raise("review", review)
        destinations = {
            "COUNTEREVIDENCE": "counterevidence/review.json",
            "NOVELTY": "novelty.json",
            "KNOWN_ISSUE": "known-issue.json",
            "MATERIALITY": "materiality.json",
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            destinations[normalized_type],
            review,
            actor=actor,
            event_type=f"{normalized_type}_REVIEW_RECORDED",
            schema_name="review",
        )
        return review

    @_compound_run_mutation
    def replay(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        allowed_executables: list[str],
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REPLAY)
        if self.project.current_state(run_id, candidate_id) is not State.SUPPORTED:
            raise PolicyError("Independent replay requires SUPPORTED state.")
        root = self.project.candidate_dir(run_id, candidate_id)
        original = read_json(root / "experiment" / "result.json")
        plan = read_json(root / "experiment" / "plan.json")
        started_at = utc_now()
        executions, refs, environment, denied = self._execute_plan(
            run_id=run_id,
            candidate_id=candidate_id,
            actor=actor,
            allowed_executables=allowed_executables,
            replay=True,
        )
        artifact_byte_limit = plan.get("isolation", {}).get("limits", {}).get("disk_bytes")
        capture_complete = capture_executions_complete(
            original.get("executions"),
            store=self.store,
            artifact_byte_limit=artifact_byte_limit,
        ) and capture_executions_complete(
            executions,
            store=self.store,
            artifact_byte_limit=artifact_byte_limit,
        )
        signatures_match = False
        if capture_complete:
            try:
                original_signature = [
                    {
                        "exit_code": item["exit_code"],
                        "stdout": item["stdout_ref"]["sha256"],
                        "stderr": item["stderr_ref"]["sha256"],
                    }
                    for item in original["executions"]
                ]
                replay_signature = [
                    {
                        "exit_code": item["exit_code"],
                        "stdout": item["stdout_ref"]["sha256"],
                        "stderr": item["stderr_ref"]["sha256"],
                    }
                    for item in executions
                ]
                signatures_match = replay_signature == original_signature
            except (KeyError, TypeError):
                signatures_match = False
        core_match = not denied and capture_complete and signatures_match
        command_records: list[dict[str, Any]] = []
        evidence_hashes: list[str] = []
        for index, execution in enumerate(executions, start=1):
            metadata = self.store.put_bytes(
                canonical_json(execution),
                media_type="application/json",
                original_name=f"replay-{index:04d}.json",
            )
            command_records.append(metadata.to_reference(schema_name="experiment-execution"))
            evidence_hashes.append(metadata.sha256)
        bundle = self.project.read_candidate(run_id, candidate_id)
        input_manifest_hash = hash_json(environment["input_manifest"])
        result = {
            "schema_version": SCHEMA_VERSION,
            "replay_id": f"RP-{candidate_id[2:]}",
            "run_id": run_id,
            "source_run_id": run_id,
            "hypothesis_id": bundle["hypothesis"]["hypothesis_id"],
            "started_at": started_at,
            "completed_at": utc_now(),
            "status": "PASS" if core_match else ("INCONCLUSIVE" if denied else "FAIL"),
            "clean_environment": capture_complete,
            "environment_hash": hash_json(environment),
            "core_result_match": core_match,
            "residual_state_detected": not capture_complete,
            "command_result_refs": command_records,
            "evidence_hashes": sorted(set(evidence_hashes)),
            "reproducer": actor.to_dict(),
            "independence_attestation": {
                "no_explorer_state": capture_complete,
                "no_unrecorded_files": capture_complete,
                "input_manifest_hash": input_manifest_hash,
            },
        }
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/environment.json",
            environment,
            actor=actor,
            event_type="REPLAY_ENVIRONMENT_RECORDED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/result.json",
            result,
            actor=actor,
            event_type="REPLAY_COMPLETED",
            schema_name="replay-result",
        )
        for execution in executions:
            self.project.append_candidate_record(
                run_id,
                candidate_id,
                "replay/commands.jsonl",
                execution,
                actor=actor,
                event_type="REPLAY_COMMAND_RECORDED",
            )
        if core_match:
            self.project.transition_candidate(
                run_id,
                candidate_id,
                State.REPRODUCED,
                actor=actor,
                reason="Independent fresh-worktree replay matched recorded core outputs.",
            )
        return result

    @_compound_run_mutation
    def import_external_replay(
        self,
        run_id: str,
        candidate_id: str,
        *,
        actor: Actor,
        result_path: Path,
        environment_path: Path,
    ) -> dict[str, Any]:
        require_capability(actor, Capability.REPLAY)
        if self.project.current_state(run_id, candidate_id) is not State.SUPPORTED:
            raise PolicyError("Independent replay import requires SUPPORTED state.")
        result = read_json(result_path)
        environment = read_json(environment_path)
        validate_or_raise("replay-result", result)
        bundle = self.project.read_candidate(run_id, candidate_id)
        original_environment = read_json(
            self.project.candidate_dir(run_id, candidate_id) / "experiment" / "environment.json"
        )
        expected_input_manifest = original_environment.get("input_manifest")
        if not isinstance(expected_input_manifest, dict):
            raise PolicyError("Original experiment input manifest is missing or invalid.")
        if any(
            (
                result["run_id"] != run_id,
                result["source_run_id"] != run_id,
                result["hypothesis_id"] != bundle["hypothesis"]["hypothesis_id"],
                result["reproducer"]["actor_id"] != actor.actor_id,
                environment.get("input_manifest") != expected_input_manifest,
                result["independence_attestation"]["input_manifest_hash"]
                != hash_json(expected_input_manifest),
            )
        ):
            raise PolicyError("External replay identity does not match this run and reproducer.")
        if result["status"] == "PASS":
            limits = environment.get("limits_enforced", {})
            if not all(
                (
                    environment.get("fresh_git_worktree") is True,
                    environment.get("network_isolated") is True,
                    environment.get("secret_isolation") == "enforced",
                    bool(limits) and all(value is True for value in limits.values()),
                )
            ):
                raise PolicyError("A passing external replay lacks enforced isolation evidence.")
            isolation = environment.get("isolation_attestation", {})
            receipt = isolation.get("receipt_ref", {})
            digest = receipt.get("sha256", "")
            receipt_valid = (
                isinstance(digest, str)
                and len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest)
                and self.store.verify(digest).valid
            )
            if not all(
                (
                    isinstance(isolation.get("issuer"), str),
                    bool(isolation.get("issuer")),
                    set(isolation.get("claims", []))
                    == {
                        "NETWORK_ISOLATED",
                        "RESOURCE_LIMITS_ENFORCED",
                        "SECRET_FREE",
                    },
                    receipt.get("artifact_id") == f"sha256:{digest}",
                    receipt.get("uri") == f"cas://sha256/{digest}",
                    receipt_valid,
                )
            ):
                raise PolicyError(
                    "A passing external replay lacks a well-formed isolation receipt reference."
                )
            expected_receipt = {
                "schema_version": SCHEMA_VERSION,
                "issuer": isolation["issuer"],
                "claims": sorted(isolation["claims"]),
                "status": "ATTESTED",
                "subject": {
                    "run_id": run_id,
                    "source_run_id": result["source_run_id"],
                    "hypothesis_id": result["hypothesis_id"],
                    "reproducer_actor_id": actor.actor_id,
                    "input_manifest_hash": hash_json(expected_input_manifest),
                    "command_result_sha256s": [
                        reference["sha256"] for reference in result["command_result_refs"]
                    ],
                },
            }
            try:
                receipt_document = read_json(self.store.get_path(digest))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise PolicyError(
                    "The external isolation receipt is not valid JSON evidence."
                ) from exc
            if receipt_document != expected_receipt:
                raise PolicyError(
                    "The external isolation receipt is not bound to this replay result."
                )
        if result["environment_hash"] != hash_json(environment):
            raise PolicyError(
                "External replay environment_hash does not match the imported environment."
            )
        for reference in _cas_references_for_import(result):
            self.store.verify_or_raise(reference["sha256"])
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/environment.json",
            environment,
            actor=actor,
            event_type="EXTERNAL_REPLAY_ENVIRONMENT_IMPORTED",
        )
        self.project.write_candidate_artifact(
            run_id,
            candidate_id,
            "replay/result.json",
            result,
            actor=actor,
            event_type="EXTERNAL_REPLAY_IMPORTED",
            schema_name="replay-result",
        )
        if result["status"] == "PASS":
            self.project.transition_candidate(
                run_id,
                candidate_id,
                State.REPRODUCED,
                actor=actor,
                reason="Externally isolated replay bundle passed schema and artifact checks.",
            )
        return result


def artifact_reference_for_file(
    store: ArtifactStore, path: Path
) -> tuple[ArtifactMetadata, dict[str, Any]]:
    metadata = store.put_file(path, media_type="application/json")
    return metadata, metadata.to_reference()


def file_sha(path: Path) -> str:
    return sha256_file(path)


def _cas_references_for_import(value: Any) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if (
            isinstance(value.get("sha256"), str)
            and isinstance(value.get("uri"), str)
            and value["uri"].startswith("cas://sha256/")
        ):
            references.append(value)
        for item in value.values():
            references.extend(_cas_references_for_import(item))
    elif isinstance(value, list):
        for item in value:
            references.extend(_cas_references_for_import(item))
    return references
