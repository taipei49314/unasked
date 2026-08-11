from __future__ import annotations

import json

import pytest

from unasked.errors import IntegrityError
from unasked.records import append_jsonl, read_jsonl


def test_jsonl_is_append_only_and_hash_verified(tmp_path) -> None:
    path = tmp_path / "records.jsonl"
    append_jsonl(path, {"id": "one", "value": 1})
    append_jsonl(path, {"id": "two", "value": 2})
    assert [record["id"] for record in read_jsonl(path)] == ["one", "two"]

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["value"] = 9
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="hash mismatch"):
        read_jsonl(path)
