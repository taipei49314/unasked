from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest

import unasked.workflow as workflow_module
from unasked.artifacts import ArtifactStore
from unasked.errors import IntegrityError, PolicyError, UsageError
from unasked.util import canonical_json
from unasked.workflow import (
    _capture_worktree_mutations,
    _normalize_experiment_commands,
    _scan_worktree,
    capture_executions_complete,
)


def _command(command_id: str = "CMD-PROBE", executable: str = "python") -> dict:
    return {
        "command_id": command_id,
        "argv": [executable, "-V"],
        "working_directory": ".",
        "purpose": "Run a bounded fixture probe.",
        "expected_observation": "The fixture exits deterministically.",
    }


def _capture_manifest(*, complete: bool = True) -> dict:
    return {
        "artifact_bytes": 0,
        "capture": "authority_filesystem_manifest_v1",
        "change_count": 0,
        "changes": [],
        "complete": complete,
        "reason_codes": [] if complete else ["CAPTURE_ARTIFACT_LIMIT_EXCEEDED"],
        "scope": "worktree_and_git_metadata",
    }


def test_capture_manifest_rejects_a_non_mapping_descriptor_even_if_prevalidated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _capture_manifest()
    manifest["change_count"] = 1
    manifest["changes"] = [
        {
            "change": "ADDED",
            "before": None,
            "after": "not-a-descriptor",
        }
    ]
    monkeypatch.setattr(workflow_module, "_valid_capture_descriptor", lambda value: True)

    valid, references = workflow_module._valid_complete_capture_manifest(
        manifest,
        store=ArtifactStore(tmp_path / "artifacts"),
        artifact_byte_limit=1024,
    )

    assert valid is False
    assert references == []


def _stored_capture(
    store: ArtifactStore,
    manifest: dict,
    mutation_refs: list[dict] | None = None,
) -> dict:
    started_at = "2000-01-01T00:00:00Z"
    completed_at = "2000-01-01T00:00:01Z"
    stdout = canonical_json(manifest)
    stderr = b"" if manifest.get("complete") is True else b"capture incomplete"
    stdout_meta = store.put_bytes(
        stdout,
        media_type="text/plain; charset=utf-8",
        original_name="CMD-CAPTURE-DIFF.stdout.txt",
    )
    stderr_meta = store.put_bytes(
        stderr,
        media_type="text/plain; charset=utf-8",
        original_name="CMD-CAPTURE-DIFF.stderr.txt",
    )
    execution_record = {
        "argv": [
            "unasked-internal",
            "capture-worktree-mutations",
            "--format=canonical-json",
        ],
        "completed_at": completed_at,
        "cwd": ".",
        "exit_code": 0 if manifest.get("complete") is True else 1,
        "expected_observation": "A complete canonical mutation manifest, possibly empty.",
        "isolation": "internal_authority_capture",
        "network_isolated": False,
        "purpose": "Capture every sandbox-only filesystem and Git-metadata mutation.",
        "resolved_executable": "unasked-internal",
        "started_at": started_at,
        "stderr": stderr.decode("utf-8"),
        "stdout": stdout.decode("utf-8"),
        "timed_out": False,
    }
    record_meta = store.put_bytes(
        canonical_json(execution_record),
        media_type="application/json",
        original_name="CMD-CAPTURE-DIFF.execution.json",
    )
    stdout_ref = stdout_meta.to_reference()
    return {
        "command_id": "CMD-CAPTURE-DIFF",
        "started_at": started_at,
        "completed_at": completed_at,
        "exit_code": execution_record["exit_code"],
        "stdout_ref": stdout_ref,
        "stderr_ref": stderr_meta.to_reference(),
        "diff_ref": stdout_ref,
        "artifact_refs": [
            record_meta.to_reference(schema_name="execution-record"),
            *(mutation_refs or []),
        ],
    }


def test_system_diff_command_is_appended_exactly_without_mutating_input() -> None:
    commands = [_command()]
    original = copy.deepcopy(commands)

    normalized = _normalize_experiment_commands(commands)

    assert commands == original
    assert normalized[:-1] == original
    assert normalized[-1] == {
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


@pytest.mark.parametrize(
    "executable",
    [
        "git",
        "git.exe",
        "/usr/bin/git",
        "C:\\Git\\git.exe",
        "C:\\Git\\git.exe.",
        "C:\\Git\\git.exe ",
        "C:\\Git\\git.exe::$DATA",
    ],
)
def test_model_authored_git_commands_are_rejected(executable: str) -> None:
    with pytest.raises(PolicyError, match="Model-authored Git"):
        _normalize_experiment_commands([_command(executable=executable)])


def test_resolved_git_identity_is_rejected_even_when_argv_name_is_disguised() -> None:
    from unasked.workflow import _reject_model_git_command

    trusted_git = Path(__file__).resolve()
    with pytest.raises(PolicyError, match="Model-authored Git"):
        _reject_model_git_command(
            _command(executable="apparently-safe-tool"),
            resolved_executable=trusted_git,
            trusted_git=trusted_git,
        )


def test_reserved_or_duplicate_command_ids_are_rejected() -> None:
    with pytest.raises(PolicyError, match="reserved"):
        _normalize_experiment_commands([_command(command_id="CMD-CAPTURE-DIFF")])
    with pytest.raises(UsageError, match="unique"):
        _normalize_experiment_commands([_command(), _command()])


def test_internal_capture_includes_tracked_untracked_and_git_metadata_mutations(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    git_dir = worktree / ".git"
    git_dir.mkdir(parents=True)
    (worktree / "tracked.txt").write_text("before\n", encoding="utf-8")
    (git_dir / "index").write_bytes(b"index-before")
    baseline = _scan_worktree(worktree)

    (worktree / "tracked.txt").write_text("after\n", encoding="utf-8")
    (worktree / "untracked.txt").write_text("new\n", encoding="utf-8")
    (git_dir / "index").write_bytes(b"index-after")
    (worktree / "empty-directory").mkdir()

    store = ArtifactStore(tmp_path / "artifacts")
    manifest, references = _capture_worktree_mutations(
        worktree,
        baseline,
        store=store,
        artifact_byte_limit=1024,
    )

    changed_paths = {
        (change["after"] or change["before"])["path"] for change in manifest["changes"]
    }
    assert manifest["complete"] is True
    assert {
        ".git/index",
        "empty-directory",
        "tracked.txt",
        "untracked.txt",
    } <= changed_paths
    assert len(references) == 3
    assert all(store.verify(reference["sha256"]).valid for reference in references)
    assert capture_executions_complete(
        [_stored_capture(store, manifest, references)],
        store=store,
        artifact_byte_limit=1024,
    )
    assert not capture_executions_complete(
        [_stored_capture(store, manifest, references)],
        store=store,
        artifact_byte_limit=manifest["artifact_bytes"] - 1,
    )


def test_capture_rejects_replaced_worktree_root_without_storing_external_bytes(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "tracked.txt").write_text("before\n", encoding="utf-8")
    baseline = _scan_worktree(worktree)
    moved = tmp_path / "moved-worktree"
    worktree.rename(moved)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("must not enter CAS\n", encoding="utf-8")
    try:
        worktree.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory links are not available: {exc}")
    store = ArtifactStore(tmp_path / "artifacts")

    with pytest.raises(IntegrityError, match="root identity|reparse point"):
        _capture_worktree_mutations(
            worktree,
            baseline,
            store=store,
            artifact_byte_limit=1024,
        )

    assert not any(path.is_file() for path in store.root.rglob("*"))


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data stream regression")
def test_capture_fails_closed_when_an_ntfs_stream_is_added(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    tracked = worktree / "tracked.txt"
    tracked.write_text("visible\n", encoding="utf-8")
    baseline = _scan_worktree(worktree)
    Path(f"{tracked}:hidden").write_bytes(b"hidden mutation")
    store = ArtifactStore(tmp_path / "artifacts")

    with pytest.raises(IntegrityError, match="alternate data streams"):
        _capture_worktree_mutations(
            worktree,
            baseline,
            store=store,
            artifact_byte_limit=1024,
        )


def test_capture_completeness_accepts_only_one_final_authentic_manifest(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    capture = _stored_capture(store, _capture_manifest())

    assert capture_executions_complete([capture], store=store, artifact_byte_limit=0) is True
    assert capture_executions_complete([], store=store, artifact_byte_limit=0) is False
    assert (
        capture_executions_complete([capture, capture], store=store, artifact_byte_limit=0) is False
    )

    ordinary = copy.deepcopy(capture)
    ordinary["command_id"] = "CMD-PROBE"
    assert (
        capture_executions_complete([capture, ordinary], store=store, artifact_byte_limit=0)
        is False
    )


@pytest.mark.parametrize("tampering", ["missing", "forged", "duplicate"])
def test_capture_completeness_rejects_invalid_manifest_cas_bindings(
    tmp_path: Path,
    tampering: str,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    if tampering == "missing":
        capture = _stored_capture(store, {})
    elif tampering == "forged":
        manifest = _capture_manifest()
        manifest["reason_codes"] = ["CAPTURE_ARTIFACT_LIMIT_EXCEEDED"]
        capture = _stored_capture(store, manifest)
    else:
        capture = _stored_capture(store, _capture_manifest())
        capture["artifact_refs"].append(copy.deepcopy(capture["artifact_refs"][0]))

    assert capture_executions_complete([capture], store=store, artifact_byte_limit=0) is False


@pytest.mark.parametrize("tampering", ["missing", "forged"])
def test_capture_completeness_rejects_missing_or_forged_cas_reference(
    tmp_path: Path,
    tampering: str,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    capture = _stored_capture(store, _capture_manifest())
    if tampering == "missing":
        capture["stdout_ref"] = {
            "artifact_id": f"sha256:{'0' * 64}",
            "sha256": "0" * 64,
            "uri": f"cas://sha256/{'0' * 64}",
            "media_type": "application/json",
            "size_bytes": 0,
        }
        capture["diff_ref"] = copy.deepcopy(capture["stdout_ref"])
    else:
        capture["stdout_ref"]["size_bytes"] += 1
        capture["diff_ref"] = copy.deepcopy(capture["stdout_ref"])

    assert capture_executions_complete([capture], store=store, artifact_byte_limit=0) is False


def test_tiny_capture_disk_limit_is_explicitly_incomplete(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    baseline = _scan_worktree(worktree)
    (worktree / "larger-than-limit.bin").write_bytes(b"xx")

    manifest, references = _capture_worktree_mutations(
        worktree,
        baseline,
        store=ArtifactStore(tmp_path / "artifacts"),
        artifact_byte_limit=1,
    )

    assert manifest["complete"] is False
    assert manifest["reason_codes"] == ["CAPTURE_ARTIFACT_LIMIT_EXCEEDED"]
    assert manifest["artifact_bytes"] == 0
    assert "after_artifact" not in manifest["changes"][0]
    assert references == []
