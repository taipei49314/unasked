from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from unasked.artifacts import ArtifactStore
from unasked.baseline import run_deterministic_baseline
from unasked.errors import IntegrityError
from unasked.policy import Actor
from unasked.project import Project
from unasked.util import canonical_json, hash_json, read_json, write_json


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    continue-on-error: true\n",
        encoding="utf-8",
    )
    (root / "src" / "module.py").write_text("unused = 1  # noqa: F841\n", encoding="utf-8")
    (root / "tests" / "test_module.py").write_text(
        "import pytest\n\n@pytest.mark.skip(reason='fixture')\ndef test_value():\n    pass\n",
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(
        root,
        "-c",
        "user.name=UNASKED Test",
        "-c",
        "user.email=unasked@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    return root


def _project(tmp_path: Path) -> tuple[Project, Path, dict]:
    repository = _repository(tmp_path)
    project = Project.create(tmp_path / "evidence")
    run = project.create_run(
        repository,
        commit=_git(repository, "rev-parse", "HEAD"),
        actor=Actor("EXP-BASELINE", "explorer"),
    )
    return project, repository, run


def _file_manifest(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_baseline_is_deterministic_snapshot_bound_and_read_only(tmp_path: Path) -> None:
    project, repository, run = _project(tmp_path)
    before = _file_manifest(project.root)

    first = run_deterministic_baseline(project, run["run_id"])
    after = _file_manifest(project.root)

    assert before == after
    assert first["run_id"] == run["run_id"]
    assert first["snapshot_hash"] == run["target"]["snapshot_hash"]
    assert first["snapshot_commit"] == run["target"]["repository_commit"]
    assert first["protocol_hash"] == run["protocol"]["sha256"]
    assert first["claim_scope"] == "NON_DISCOVERY_SIGNAL_ONLY"
    assert first["lifecycle_effect"] == "NONE"

    categories = [record["category"] for record in first["signals"]]
    assert categories == ["continue_on_error", "skip", "suppression"]
    assert first["signal_count"] == 3
    for record in first["signals"]:
        assert record["run_id"] == run["run_id"]
        assert record["snapshot_hash"] == run["target"]["snapshot_hash"]
        assert record["protocol_hash"] == run["protocol"]["sha256"]
        assert record["claim_scope"] == "NON_DISCOVERY_SIGNAL_ONLY"
        unhashed = {key: value for key, value in record.items() if key != "record_hash"}
        assert record["record_hash"] == hash_json(unhashed)

    # Mutable worktree bytes are not evidence.  The result remains pinned to the
    # committed Git objects even if the checkout changes after run creation.
    (repository / "src" / "module.py").write_text("clean = True\n", encoding="utf-8")
    (repository / "untracked.py").write_text("value = 1  # noqa\n", encoding="utf-8")
    second = run_deterministic_baseline(project, run["run_id"])
    assert second == first

    rendered = json.dumps(first, sort_keys=True)
    assert '"VERIFIED"' not in rendered
    assert '"verdict"' not in rendered
    assert '"candidate_id"' not in rendered


def test_baseline_reports_normalized_budget_and_is_cas_ready(tmp_path: Path) -> None:
    project, _, run = _project(tmp_path)
    result = run_deterministic_baseline(project, run["run_id"])
    budget = result["normalized_budget"]
    usage = budget["usage"]

    expected = (
        usage["snapshot_entries"] + usage["snapshot_kib_units"] + usage["observations_classified"]
    )
    assert budget["consumed_units"] == expected
    assert budget["workload_bound_units"] == expected
    assert budget["within_workload_bound"] is True
    assert usage["snapshot_passes"] == 1
    assert usage["model_calls"] == 0
    assert usage["network_requests"] == 0
    assert usage["experiment_commands"] == 0

    payload = canonical_json(result)
    store = ArtifactStore(project.artifacts_root)
    metadata = store.put_bytes(
        payload,
        media_type=result["integration"]["media_type"],
        original_name="deterministic-baseline.json",
    )
    assert metadata.sha256 == hash_json(result)
    assert store.verify(metadata.sha256).valid is True


def test_baseline_rejects_protocol_binding_drift(tmp_path: Path) -> None:
    project, _, run = _project(tmp_path)
    protocol_path = project.paths(run["run_id"]).protocol
    protocol = read_json(protocol_path)
    protocol["claim"] = "mutated after freeze"
    write_json(protocol_path, protocol)

    with pytest.raises(IntegrityError, match="protocol hash"):
        run_deterministic_baseline(project, run["run_id"])
