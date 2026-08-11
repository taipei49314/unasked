"""Discover and export the source-bound resource kit shipped with UNASKED."""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

from unasked.errors import IntegrityError, PolicyError
from unasked.util import atomic_write, sha256_bytes

_RESOURCE_DIRECTORIES = ("constitution", "custody", "examples", "protocols", "templates")
_RESOURCE_FILES = ("unasked-threat-model.md",)


def _source_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _bundled_root() -> Traversable:
    packaged = files("unasked.bundled")
    if all(packaged.joinpath(name).is_dir() for name in _RESOURCE_DIRECTORIES) and all(
        packaged.joinpath(name).is_file() for name in _RESOURCE_FILES
    ):
        return packaged
    source = _source_root()
    if all((source / name).is_dir() for name in _RESOURCE_DIRECTORIES) and all(
        (source / name).is_file() for name in _RESOURCE_FILES
    ):
        return source
    raise IntegrityError("The bundled UNASKED resource kit is incomplete.")


def _walk(root: Traversable, relative: str) -> list[tuple[str, bytes]]:
    current = root.joinpath(*relative.split("/"))
    if current.is_file():
        return [(relative, current.read_bytes())]
    if not current.is_dir():
        raise IntegrityError("A bundled resource path is missing.", details={"path": relative})
    discovered: list[tuple[str, bytes]] = []
    for child in sorted(current.iterdir(), key=lambda item: item.name):
        child_relative = f"{relative}/{child.name}"
        if child.is_dir():
            discovered.extend(_walk(root, child_relative))
        elif child.is_file():
            discovered.append((child_relative, child.read_bytes()))
    return discovered


def _resource_entries() -> list[tuple[str, bytes]]:
    root = _bundled_root()
    entries: list[tuple[str, bytes]] = []
    for relative in (*_RESOURCE_DIRECTORIES, *_RESOURCE_FILES):
        entries.extend(_walk(root, relative))
    return sorted(entries, key=lambda item: item[0])


def list_bundled_resources() -> tuple[dict[str, Any], ...]:
    """Return exact resource paths, byte sizes, and hashes in lexical order."""

    return tuple(
        {
            "path": relative,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        }
        for relative, data in _resource_entries()
    )


def export_bundled_resources(
    destination: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export the exact resource kit without silently replacing changed files."""

    root = Path(destination).expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise PolicyError("Resource destination must be a directory.", details={"path": str(root)})
    root.mkdir(parents=True, exist_ok=True)
    exported: list[dict[str, Any]] = []
    for relative, data in _resource_entries():
        target = root.joinpath(*relative.split("/"))
        status = "CREATED"
        if target.exists():
            if not target.is_file():
                raise PolicyError(
                    "A resource destination path is not a file.", details={"path": str(target)}
                )
            if target.read_bytes() == data:
                status = "UNCHANGED"
            elif not overwrite:
                raise PolicyError(
                    "A resource destination file already has different content.",
                    details={"path": str(target)},
                )
            else:
                status = "REPLACED"
        if status != "UNCHANGED":
            atomic_write(target, data)
        exported.append(
            {
                "path": relative,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "status": status,
            }
        )
    return {
        "destination": str(root),
        "resource_count": len(exported),
        "files": exported,
    }


__all__ = ["export_bundled_resources", "list_bundled_resources"]
