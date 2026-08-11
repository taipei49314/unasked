from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO

from unasked.errors import IntegrityError, NotFoundError, PolicyError, UsageError
from unasked.util import (
    atomic_write,
    canonical_json,
    ensure_within,
    sha256_bytes,
    sha256_file,
    utc_now,
)

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
METADATA_FIELDS = {"sha256", "size", "media_type", "created_at", "original_name"}


def _validate_digest(value: str | ArtifactMetadata) -> str:
    if isinstance(value, ArtifactMetadata):
        value = value.sha256
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise UsageError("Artifact digest must be exactly 64 hexadecimal SHA-256 characters.")
    return value.lower()


def _validate_original_name(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise UsageError("original_name must be a non-empty file name.")
    if value in {".", ".."} or "/" in value or "\\" in value or ":" in value:
        raise PolicyError(
            "original_name must not contain a path.",
            details={"original_name": value},
        )
    return value


def _validate_media_type(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\r" in value or "\n" in value:
        raise UsageError("media_type must be a non-empty, single-line string.")
    return value


def _validate_created_at(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("created_at must be a non-empty string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a UTC offset")


@dataclass(frozen=True, slots=True)
class ArtifactMetadata(Mapping[str, Any]):
    sha256: str
    size: int
    media_type: str
    created_at: str
    original_name: str | None = None
    path: Path = field(default=Path(), repr=False, compare=False)

    @property
    def size_bytes(self) -> int:
        return self.size

    @property
    def artifact_id(self) -> str:
        return f"sha256:{self.sha256}"

    @property
    def uri(self) -> str:
        return f"cas://sha256/{self.sha256}"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "created_at": self.created_at,
        }
        if self.original_name is not None:
            value["original_name"] = self.original_name
        return value

    def to_reference(self, *, schema_name: str | None = None) -> dict[str, Any]:
        value: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "uri": self.uri,
            "media_type": self.media_type,
            "size_bytes": self.size,
        }
        if schema_name is not None:
            value["schema_name"] = schema_name
        return value

    def __getitem__(self, key: str) -> Any:
        try:
            return self.to_dict()[key]
        except KeyError:
            raise KeyError(key) from None

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def __str__(self) -> str:
        return self.sha256


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    valid: bool
    sha256: str
    path: Path
    size: int | None = None
    metadata: ArtifactMetadata | None = None
    error: str | None = None
    missing: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "sha256": self.sha256,
            "path": str(self.path),
            "size": self.size,
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "error": self.error,
            "missing": self.missing,
            "details": dict(self.details),
        }

    def raise_for_error(self) -> None:
        if self.valid:
            return
        error_type = NotFoundError if self.missing else IntegrityError
        raise error_type(
            self.error or "Artifact verification failed.",
            details=self.to_dict(),
        )


class ArtifactStore:
    """Immutable SHA-256 content-addressed storage with sidecar metadata."""

    def __init__(self, root: str | Path) -> None:
        supplied_root = Path(root)
        supplied_root.mkdir(parents=True, exist_ok=True)
        if not supplied_root.is_dir():
            raise UsageError("Artifact store root must be a directory.")
        self.root = supplied_root.resolve()
        self._objects = self.root / "objects" / "sha256"
        self._metadata = self.root / "metadata" / "sha256"
        self._temporary = self.root / ".tmp"

    def _content_path(self, digest: str | ArtifactMetadata) -> Path:
        normalized = _validate_digest(digest)
        return ensure_within(self._objects / normalized[:2] / normalized, self.root)

    def _metadata_path(self, digest: str | ArtifactMetadata) -> Path:
        normalized = _validate_digest(digest)
        return ensure_within(self._metadata / normalized[:2] / f"{normalized}.json", self.root)

    def path_for(self, digest: str | ArtifactMetadata) -> Path:
        """Return the deterministic path; existence and integrity are not implied."""

        return self._content_path(digest)

    def _read_metadata(self, digest: str | ArtifactMetadata) -> ArtifactMetadata:
        normalized = _validate_digest(digest)
        path = self._metadata_path(normalized)
        if not path.exists():
            raise NotFoundError(
                "Artifact metadata was not found.",
                details={"sha256": normalized, "path": str(path)},
            )
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(
                "Artifact metadata is not a regular file.",
                details={"sha256": normalized, "path": str(path)},
            )
        try:
            raw = path.read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrityError(
                "Artifact metadata is not valid UTF-8 JSON.",
                details={"sha256": normalized, "path": str(path), "reason": str(exc)},
            ) from exc
        if not isinstance(value, dict):
            raise IntegrityError("Artifact metadata must be a JSON object.")
        if raw != canonical_json(value) + b"\n":
            raise IntegrityError(
                "Artifact metadata is not encoded as canonical JSON.",
                details={"sha256": normalized, "path": str(path)},
            )
        unknown = sorted(set(value).difference(METADATA_FIELDS))
        required = {"sha256", "size", "media_type", "created_at"}
        missing = sorted(required.difference(value))
        if unknown or missing:
            raise IntegrityError(
                "Artifact metadata fields are invalid.",
                details={"sha256": normalized, "unknown": unknown, "missing": missing},
            )
        try:
            if value["sha256"] != normalized:
                raise ValueError("metadata digest does not match its address")
            if isinstance(value["size"], bool) or not isinstance(value["size"], int):
                raise ValueError("size must be an integer")
            if value["size"] < 0:
                raise ValueError("size must not be negative")
            media_type = _validate_media_type(value["media_type"])
            _validate_created_at(value["created_at"])
            original_name = _validate_original_name(value.get("original_name"))
        except (PolicyError, UsageError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "Artifact metadata contains invalid values.",
                details={"sha256": normalized, "reason": str(exc)},
            ) from exc
        return ArtifactMetadata(
            sha256=normalized,
            size=value["size"],
            media_type=media_type,
            created_at=value["created_at"],
            original_name=original_name,
            path=self._content_path(normalized),
        )

    def _write_or_load_metadata(
        self,
        digest: str,
        *,
        size: int,
        media_type: str,
        original_name: str | None,
    ) -> ArtifactMetadata:
        metadata_path = self._metadata_path(digest)
        if metadata_path.exists():
            existing = self._read_metadata(digest)
            if existing.size != size:
                raise IntegrityError(
                    "Existing artifact metadata has the wrong size.",
                    details={"sha256": digest, "expected": size, "actual": existing.size},
                )
            return existing

        value: dict[str, Any] = {
            "sha256": digest,
            "size": size,
            "media_type": media_type,
            "created_at": utc_now(),
        }
        if original_name is not None:
            value["original_name"] = original_name
        atomic_write(metadata_path, canonical_json(value) + b"\n")
        return self._read_metadata(digest)

    def _validate_existing_content(self, digest: str, *, size: int | None = None) -> Path:
        path = self._content_path(digest)
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(
                "The content-addressed artifact path is not a regular file.",
                details={"sha256": digest, "path": str(path)},
            )
        actual_size = path.stat().st_size
        if size is not None and actual_size != size:
            raise IntegrityError(
                "Existing content at the artifact address has the wrong size.",
                details={"sha256": digest, "expected": size, "actual": actual_size},
            )
        actual_digest = sha256_file(path)
        if actual_digest != digest:
            raise IntegrityError(
                "Existing content at the artifact address is corrupt.",
                details={"sha256": digest, "actual": actual_digest, "path": str(path)},
            )
        return path

    def put_bytes(
        self,
        data: bytes | bytearray | memoryview,
        *,
        media_type: str = "application/octet-stream",
        original_name: str | None = None,
    ) -> ArtifactMetadata:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise UsageError("Artifact data must be bytes-like.")
        value = bytes(data)
        media_type = _validate_media_type(media_type)
        original_name = _validate_original_name(original_name)
        digest = sha256_bytes(value)
        path = self._content_path(digest)

        if path.exists() or path.is_symlink():
            self._validate_existing_content(digest, size=len(value))
        else:
            atomic_write(path, value)
            self._validate_existing_content(digest, size=len(value))
        return self._write_or_load_metadata(
            digest,
            size=len(value),
            media_type=media_type,
            original_name=original_name,
        )

    store_bytes = put_bytes
    add_bytes = put_bytes

    def put_file(
        self,
        source: str | Path,
        *,
        media_type: str | None = None,
        original_name: str | None = None,
    ) -> ArtifactMetadata:
        source_path = Path(source)
        if not source_path.is_file():
            raise NotFoundError(
                "Artifact source file was not found.",
                details={"path": str(source_path)},
            )
        selected_name = _validate_original_name(
            source_path.name if original_name is None else original_name
        )
        selected_type = _validate_media_type(
            media_type or mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
        )

        self._temporary.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".artifact.", dir=self._temporary)
        temporary = Path(temporary_name)
        digest_state = hashlib.sha256()
        size = 0
        try:
            with (
                source_path.open("rb") as input_stream,
                os.fdopen(descriptor, "wb") as output_stream,
            ):
                for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                    digest_state.update(chunk)
                    size += len(chunk)
                    output_stream.write(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())

            digest = digest_state.hexdigest()
            destination = self._content_path(digest)
            if destination.exists() or destination.is_symlink():
                self._validate_existing_content(digest, size=size)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(temporary, destination)
                self._validate_existing_content(digest, size=size)
            return self._write_or_load_metadata(
                digest,
                size=size,
                media_type=selected_type,
                original_name=selected_name,
            )
        finally:
            if temporary.exists():
                temporary.unlink()

    store_file = put_file
    add_file = put_file

    def verify(self, digest: str | ArtifactMetadata) -> ArtifactVerification:
        normalized = _validate_digest(digest)
        path = self._content_path(normalized)
        metadata_path = self._metadata_path(normalized)
        if not path.exists() and not metadata_path.exists():
            return ArtifactVerification(
                False,
                normalized,
                path,
                error="Artifact content and metadata were not found.",
                missing=True,
            )
        if path.is_symlink() or not path.is_file():
            return ArtifactVerification(
                False,
                normalized,
                path,
                error="Artifact content is missing or is not a regular file.",
                missing=not path.exists(),
            )
        try:
            metadata = self._read_metadata(normalized)
            actual_size = path.stat().st_size
            if actual_size != metadata.size:
                return ArtifactVerification(
                    False,
                    normalized,
                    path,
                    size=actual_size,
                    metadata=metadata,
                    error="Artifact size does not match its metadata.",
                    details={"expected": metadata.size, "actual": actual_size},
                )
            actual_digest = sha256_file(path)
            if actual_digest != normalized:
                return ArtifactVerification(
                    False,
                    normalized,
                    path,
                    size=actual_size,
                    metadata=metadata,
                    error="Artifact content does not match its SHA-256 address.",
                    details={"expected": normalized, "actual": actual_digest},
                )
        except NotFoundError as exc:
            return ArtifactVerification(
                False,
                normalized,
                path,
                size=path.stat().st_size,
                error=exc.message,
                missing=True,
                details=exc.details,
            )
        except (IntegrityError, OSError) as exc:
            message = exc.message if isinstance(exc, IntegrityError) else str(exc)
            details = exc.details if isinstance(exc, IntegrityError) else {}
            return ArtifactVerification(
                False,
                normalized,
                path,
                error=message,
                details=details,
            )
        return ArtifactVerification(
            True,
            normalized,
            path,
            size=metadata.size,
            metadata=metadata,
        )

    def verify_or_raise(self, digest: str | ArtifactMetadata) -> ArtifactVerification:
        report = self.verify(digest)
        report.raise_for_error()
        return report

    def get_metadata(self, digest: str | ArtifactMetadata) -> ArtifactMetadata:
        report = self.verify_or_raise(digest)
        if report.metadata is None:
            raise IntegrityError(
                "Verified artifact metadata is missing.",
                details=report.to_dict(),
            )
        return report.metadata

    metadata = get_metadata
    get = get_metadata

    def get_path(self, digest: str | ArtifactMetadata) -> Path:
        return self.verify_or_raise(digest).path

    def read_bytes(self, digest: str | ArtifactMetadata) -> bytes:
        return self.get_path(digest).read_bytes()

    def open(self, digest: str | ArtifactMetadata) -> BinaryIO:
        return self.get_path(digest).open("rb")

    def contains(self, digest: str | ArtifactMetadata, *, verified: bool = True) -> bool:
        if verified:
            return self.verify(digest).valid
        return self._content_path(digest).is_file()

    has = contains
