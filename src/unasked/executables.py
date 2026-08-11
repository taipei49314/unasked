"""Executable resolution that never treats the current directory as trusted PATH state."""

from __future__ import annotations

import os
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

_WINDOWS_NATIVE_SUFFIXES = (".exe", ".com")
_WINDOWS_SCRIPT_SUFFIXES = {".bat", ".cmd", ".ps1"}


def _normalize_windows_namespace(value: str) -> str:
    """Collapse Win32 extended-length aliases before path policy checks."""

    if value.casefold().startswith("\\\\?\\unc\\"):
        return "\\\\" + value[8:]
    if value.casefold().startswith("\\\\?\\"):
        return value[4:]
    return value


def _absolute_lexical_path(value: str | os.PathLike[str]) -> Path:
    rendered = os.path.expanduser(os.path.expandvars(os.fspath(value)))
    if os.name == "nt":
        rendered = _normalize_windows_namespace(rendered)
    return Path(os.path.abspath(rendered))


def _is_network_path(path: Path) -> bool:
    if os.name != "nt":
        return False
    rendered = _normalize_windows_namespace(os.fspath(path))
    if rendered.startswith("\\\\"):
        return True
    drive, _ = os.path.splitdrive(rendered)
    if not drive:
        return False
    try:
        import ctypes

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\")
    except (AttributeError, OSError):
        return True
    return drive_type in {0, 1, 4}


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _samefile_within(path: Path, root: Path) -> bool:
    """Use filesystem identity to catch junction, 8.3, and namespace aliases."""

    current = path
    while True:
        try:
            if os.path.samefile(current, root):
                return True
        except (FileNotFoundError, OSError, ValueError):
            pass
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _resolved_roots(values: Iterable[str | os.PathLike[str]]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for value in values:
        try:
            lexical = _absolute_lexical_path(value)
            if _is_network_path(lexical):
                continue
            root = lexical.resolve(strict=False)
        except (OSError, TypeError, ValueError):
            continue
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def _lexical_roots(values: Iterable[str | os.PathLike[str]]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for value in values:
        try:
            root = _absolute_lexical_path(value)
        except (OSError, TypeError, ValueError):
            continue
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def _candidate_names(name: str, windows_suffixes: tuple[str, ...]) -> tuple[str, ...]:
    if os.name != "nt":
        return (name,)
    suffix = Path(name).suffix.casefold()
    normalized_suffixes = tuple(item.casefold() for item in windows_suffixes)
    if suffix in _WINDOWS_SCRIPT_SUFFIXES:
        return ()
    if suffix in normalized_suffixes:
        return (name,)
    return tuple(f"{name}{suffix}" for suffix in normalized_suffixes)


@lru_cache(maxsize=128)
def _path_candidates(
    name: str,
    search_path: str,
    windows_suffixes: tuple[str, ...],
) -> tuple[tuple[Path, Path], ...]:
    """Return executable candidates in PATH order without trusting relative entries.

    PATH directory resolution is comparatively expensive on Windows and Git is
    invoked many times during an investigation.  Cache only process-global PATH
    discovery; repository-specific exclusions are applied by ``find_executable``
    on every call.
    """

    candidates: list[tuple[Path, Path]] = []
    seen_directories: set[str] = set()
    for raw_entry in search_path.split(os.pathsep):
        rendered = raw_entry.strip()
        if len(rendered) >= 2 and rendered[0] == rendered[-1] == '"':
            rendered = rendered[1:-1]
        if not rendered:
            continue
        if os.name == "nt":
            rendered = _normalize_windows_namespace(rendered)
        directory = Path(os.path.expandvars(rendered)).expanduser()
        if not directory.is_absolute():
            continue
        lexical_directory = _absolute_lexical_path(directory)
        if _is_network_path(lexical_directory):
            continue
        try:
            resolved_directory = directory.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            continue
        if not resolved_directory.is_dir():
            continue
        identity = (
            str(resolved_directory).casefold() if os.name == "nt" else str(resolved_directory)
        )
        if identity in seen_directories:
            continue
        seen_directories.add(identity)

        for candidate_name in _candidate_names(name, windows_suffixes):
            lexical_candidate = lexical_directory / candidate_name
            candidate = resolved_directory / candidate_name
            try:
                resolved = candidate.resolve(strict=True)
            except (FileNotFoundError, OSError, RuntimeError):
                continue
            if not resolved.is_file():
                continue
            if os.name != "nt" and not os.access(resolved, os.X_OK):
                continue
            candidates.append((lexical_candidate, resolved))
    return tuple(candidates)


def find_executable(
    name: str,
    *,
    path: str | None = None,
    excluded_roots: Iterable[str | os.PathLike[str]] = (),
    windows_suffixes: tuple[str, ...] = _WINDOWS_NATIVE_SUFFIXES,
) -> Path | None:
    """Resolve a bare executable name only through absolute PATH directories.

    ``shutil.which`` may consult the current directory on Windows even when it is
    absent from ``PATH``.  That behavior is unsafe while inspecting an untrusted
    repository.  Empty and relative PATH entries are therefore ignored here, and
    callers may exclude the target repository (including symlinked descendants).
    Windows command scripts are never returned.
    """

    if not isinstance(name, str) or not name or "\x00" in name:
        return None
    if Path(name).is_absolute() or "/" in name or "\\" in name:
        return None

    excluded = tuple(excluded_roots)
    roots = _resolved_roots(excluded)
    lexical_roots = _lexical_roots(excluded)
    search_path = os.environ.get("PATH", "") if path is None else path
    for lexical_candidate, candidate in _path_candidates(name, search_path, windows_suffixes):
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            continue
        if (
            any(_is_within(lexical_candidate, root) for root in lexical_roots)
            or any(_is_within(resolved, root) for root in roots)
            or any(_samefile_within(lexical_candidate, root) for root in roots)
            or any(_samefile_within(resolved, root) for root in roots)
            or not resolved.is_file()
        ):
            continue
        if os.name != "nt" and not os.access(resolved, os.X_OK):
            continue
        return resolved
    return None


def validate_absolute_executable(
    value: str | os.PathLike[str],
    *,
    windows_suffixes: tuple[str, ...] = _WINDOWS_NATIVE_SUFFIXES,
) -> Path | None:
    """Return a validated native executable only when *value* is absolute."""

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    if os.name == "nt" and resolved.suffix.casefold() not in {
        item.casefold() for item in windows_suffixes
    }:
        return None
    if os.name != "nt" and not os.access(resolved, os.X_OK):
        return None
    return resolved


__all__ = ["find_executable", "validate_absolute_executable"]
