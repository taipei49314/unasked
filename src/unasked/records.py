from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from unasked.errors import IntegrityError
from unasked.util import canonical_json, hash_json


def append_jsonl(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    """Append one canonical record and fsync it; never exposes an update/delete path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    enriched = dict(record)
    enriched.setdefault("record_hash", hash_json(record))
    line = canonical_json(enriched) + b"\n"
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, line)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return enriched


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IntegrityError(
                    "Invalid JSONL record.",
                    details={"path": str(path), "line": line_number},
                ) from exc
            if not isinstance(value, dict):
                raise IntegrityError(
                    "JSONL record must be an object.",
                    details={"path": str(path), "line": line_number},
                )
            claimed = value.get("record_hash")
            unhashed = {key: item for key, item in value.items() if key != "record_hash"}
            actual = hash_json(unhashed)
            if claimed != actual:
                raise IntegrityError(
                    "JSONL record hash mismatch.",
                    details={
                        "path": str(path),
                        "line": line_number,
                        "expected": claimed,
                        "actual": actual,
                    },
                )
            yield value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))


def verify_jsonl(path: Path) -> dict[str, Any]:
    records = read_jsonl(path)
    return {"valid": True, "path": str(path), "records": len(records)}
