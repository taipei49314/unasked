from __future__ import annotations

from pathlib import Path

import pytest

from unasked.errors import PolicyError
from unasked.resources import export_bundled_resources, list_bundled_resources
from unasked.util import sha256_bytes


def test_bundled_resources_match_source_files() -> None:
    root = Path(__file__).resolve().parents[1]
    resources = list_bundled_resources()

    assert resources
    assert {item["path"] for item in resources} >= {
        "constitution/UNASKED_NORTH_STAR_v0.1.md",
        "custody/BENCHMARK_CUSTODY_PROTOCOL.md",
        "examples/m0-budget.json",
        "examples/provider-scripted.json",
        "examples/trial-evidence-index.json",
        "examples/trial-preregistration.json",
        "protocols/m0-development-v0.1.json",
        "protocols/p0-v0.1.json",
        "templates/WORK_PACKAGE.md",
        "unasked-threat-model.md",
    }
    for item in resources:
        data = (root / item["path"]).read_bytes()
        assert item["bytes"] == len(data)
        assert item["sha256"] == sha256_bytes(data)


def test_export_is_idempotent_and_refuses_changed_files(tmp_path: Path) -> None:
    destination = tmp_path / "kit"

    first = export_bundled_resources(destination)
    second = export_bundled_resources(destination)

    assert first["resource_count"] == len(list_bundled_resources())
    assert {item["status"] for item in first["files"]} == {"CREATED"}
    assert {item["status"] for item in second["files"]} == {"UNCHANGED"}
    changed = destination / "examples" / "m0-budget.json"
    changed.write_text("{}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="different content"):
        export_bundled_resources(destination)

    replaced = export_bundled_resources(destination, overwrite=True)
    assert "REPLACED" in {item["status"] for item in replaced["files"]}
