from __future__ import annotations

import json

import pytest

from unasked.artifacts import ArtifactStore, ArtifactVerification
from unasked.errors import IntegrityError, PolicyError, UsageError
from unasked.util import canonical_json, sha256_bytes


def test_cas_stores_metadata_and_deduplicates_identical_content(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    content = b"reproducible evidence\n"

    first = store.put_bytes(
        content,
        media_type="text/plain",
        original_name="evidence.txt",
    )
    second = store.put_bytes(
        content,
        media_type="application/octet-stream",
        original_name="another.txt",
    )

    assert first.sha256 == sha256_bytes(content)
    assert first.path == second.path
    assert first.created_at == second.created_at
    assert second.media_type == "text/plain"  # first immutable metadata wins
    assert first.path.read_bytes() == content
    assert len([path for path in (store.root / "objects").rglob("*") if path.is_file()]) == 1

    metadata_path = store.root / "metadata" / "sha256" / first.sha256[:2] / f"{first.sha256}.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata_path.read_bytes() == canonical_json(metadata) + b"\n"
    assert metadata == {
        "sha256": first.sha256,
        "size": len(content),
        "media_type": "text/plain",
        "created_at": first.created_at,
        "original_name": "evidence.txt",
    }
    assert store.verify(first).valid
    assert store.read_bytes(first.sha256) == content


def test_cas_detects_content_and_metadata_corruption(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    artifact = store.put_bytes(b"trusted", original_name="trusted.bin")

    artifact.path.write_bytes(b"changed")
    report = store.verify(artifact.sha256)
    assert not report.valid
    assert "size" in (report.error or "").lower() or "sha-256" in (report.error or "").lower()
    with pytest.raises(IntegrityError):
        store.read_bytes(artifact.sha256)
    with pytest.raises(IntegrityError):
        store.put_bytes(b"trusted", original_name="trusted.bin")

    other = store.put_bytes(b"other")
    metadata_path = store.root / "metadata" / "sha256" / other.sha256[:2] / f"{other.sha256}.json"
    metadata_path.write_text('{"sha256":"wrong"}\n', encoding="utf-8")
    report = store.verify(other.sha256)
    assert not report.valid
    assert "metadata" in (report.error or "").lower()


def test_cas_streams_files_and_reopens(tmp_path) -> None:
    source = tmp_path / "command.log"
    source.write_bytes((b"0123456789" * 200_000) + b"\n")
    root = tmp_path / "artifacts"

    artifact = ArtifactStore(root).put_file(source, media_type="text/plain")
    reopened = ArtifactStore(root)

    assert reopened.verify(artifact.sha256).valid
    assert reopened.get_metadata(artifact.sha256).original_name == "command.log"
    assert reopened.get_path(artifact.sha256).read_bytes() == source.read_bytes()


def test_cas_rejects_path_traversal_inputs(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")

    with pytest.raises((PolicyError, UsageError)):
        store.put_bytes(b"data", original_name="../../outside.txt")
    with pytest.raises(UsageError):
        store.path_for("../" + "0" * 61)
    with pytest.raises(UsageError):
        store.path_for("0" * 64 + "/outside")
    assert not (tmp_path / "outside.txt").exists()


def test_cas_get_metadata_fails_closed_when_verified_metadata_is_missing(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    digest = "0" * 64
    report = ArtifactVerification(
        valid=True,
        sha256=digest,
        path=tmp_path / "missing-object",
    )
    monkeypatch.setattr(ArtifactStore, "verify_or_raise", lambda self, value: report)

    with pytest.raises(IntegrityError, match="metadata is missing"):
        store.get_metadata(digest)
