from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from unasked.observer import observe_repository
from unasked.repository import capture_snapshot, temporary_worktree


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "observed"
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "README.md").write_text(
        "# Example\n\nThis package supports deterministic widgets.\n", encoding="utf-8"
    )
    (root / "docs" / "usage.md").write_text(
        "# Usage\n\nThe command can process a widget.\n", encoding="utf-8"
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\n"
        "on:\n"
        "  push:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: pytest\n"
        "        continue-on-error: true\n",
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


def test_observations_are_deterministic_source_bound_facts(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    snapshot = capture_snapshot(repository)

    with temporary_worktree(repository, snapshot["commit"]) as worktree:
        first = observe_repository(worktree, snapshot)
        second = observe_repository(snapshot, worktree)

    assert first == second
    assert first == sorted(
        first,
        key=lambda item: (
            item["source"]["path"].encode("utf-8"),
            item["source"]["line_start"],
            item["kind"],
            item["observation_id"],
        ),
    )
    assert {item["kind"] for item in first} >= {
        "repository_structure",
        "documentation_claim_source",
        "ci_workflow_fact",
        "test_path",
        "control_signal",
    }

    required = {
        "observation_id",
        "kind",
        "source",
        "capture_method",
        "captured_at",
        "snapshot_commit",
        "integrity",
    }
    for observation in first:
        assert required <= observation.keys()
        assert observation["snapshot_commit"] == snapshot["commit"]
        assert observation["authority_scope"] == "observation_only"
        assert observation["interpretation"] == "none"
        assert observation["integrity"]["status"] == "source_bound"
        assert observation["source"]["line_start"] >= 1
        assert observation["source"]["line_end"] >= observation["source"]["line_start"]

    readme_bytes = subprocess.run(
        ["git", "-C", str(repository), "show", f"{snapshot['commit']}:README.md"],
        check=True,
        capture_output=True,
    ).stdout
    readme_observations = [item for item in first if item["source"]["path"] == "README.md"]
    assert readme_observations
    assert {item["source"]["sha256"] for item in readme_observations} == {
        hashlib.sha256(readme_bytes).hexdigest()
    }

    ci_facts = [item["fact"] for item in first if item["kind"] == "ci_workflow_fact"]
    assert any(fact["fact_type"] == "trigger" and fact["key"] == "push" for fact in ci_facts)
    assert any(fact["fact_type"] == "job" and fact["key"] == "test" for fact in ci_facts)
    assert any(fact["fact_type"] == "continue_on_error" for fact in ci_facts)

    categories = {item["fact"]["category"] for item in first if item["kind"] == "control_signal"}
    assert categories >= {"skip", "suppression", "continue_on_error"}
    rendered = json.dumps(first, sort_keys=True)
    assert '"verdict"' not in rendered
    assert '"VERIFIED"' not in rendered
