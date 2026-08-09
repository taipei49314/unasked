"""Deterministic, read-only facts from an immutable repository snapshot.

Observers in this module extract source-bound facts.  They do not decide whether
the facts are discrepant, novel, material, or a discovery.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from unasked.errors import IntegrityError, UsageError
from unasked.repository import (
    _git_blob,
    _run_git,
    _tree_entries,
    capture_snapshot,
    repository_root,
    resolve_commit,
)
from unasked.util import hash_json, sha256_bytes

_YAML_KEY_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:-[ \t]+)?(?P<key>[A-Za-z0-9_.${}{()/-]+)"
    r"[ \t]*:[ \t]*(?P<value>.*)$"
)

_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "skip",
        re.compile(
            r"(?:pytest\.mark\.(?:skip|skipif)|unittest\.(?:skip|skipIf|skipUnless)|"
            r"\b(?:it|test|describe)\.skip\b|\b(?:xit|xdescribe)\s*\(|"
            r"@(?:Disabled|Ignore)\b|\bpytest\.skip\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "suppression",
        re.compile(
            r"(?:#\s*noqa\b|#\s*type:\s*ignore\b|#\s*nosec\b|"
            r"pragma:\s*no\s*cover|eslint-disable|stylelint-disable|"
            r"noinspection|@SuppressWarnings\b|coverage:\s*ignore|"
            r"#\s*pragma:\s*allowlist\s+secret|allow\(dead_code\))",
            re.IGNORECASE,
        ),
    ),
    (
        "continue_on_error",
        re.compile(
            r"(?:continue-on-error\s*:|allow_failure\s*:|\|\|\s*true(?:\s|$))",
            re.IGNORECASE,
        ),
    ),
)

_TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".rst",
    ".sh",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _line_count(content: bytes) -> int:
    if not content:
        return 1
    return content.count(b"\n") + (0 if content.endswith(b"\n") else 1)


def _decode_text(content: bytes) -> str | None:
    if b"\0" in content:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_documentation(path: str) -> tuple[bool, str]:
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    if name.startswith("readme"):
        return True, "readme"
    if (
        "docs" in parts
        or "doc" in parts
        or name
        in {
            "contributing.md",
            "security.md",
            "support.md",
        }
    ):
        return True, "documentation"
    return False, ""


def _is_ci_workflow(path: str) -> tuple[bool, str]:
    normalized = path.lower()
    pure = PurePosixPath(normalized)
    if normalized.startswith(".github/workflows/") and pure.suffix in {".yml", ".yaml"}:
        return True, "github_actions"
    if normalized == ".gitlab-ci.yml":
        return True, "gitlab_ci"
    if normalized in {".travis.yml", ".circleci/config.yml"}:
        return True, "generic_ci"
    if pure.name.startswith("azure-pipelines") and pure.suffix in {".yml", ".yaml"}:
        return True, "azure_pipelines"
    return False, ""


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = {part.lower() for part in pure.parts[:-1]}
    name = pure.name.lower()
    if parts.intersection({"test", "tests", "spec", "specs", "__tests__"}):
        return True
    return bool(
        name.startswith(("test_", "spec_"))
        or re.search(r"(?:_test|\.test|\.spec)\.[a-z0-9]+$", name)
    )


def _is_probably_text(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix.lower() in _TEXT_EXTENSIONS or pure.name.lower() in {
        "dockerfile",
        "gemfile",
        "makefile",
    }


def _source(path: str, content: bytes, line_start: int, line_end: int) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": sha256_bytes(content),
        "line_start": line_start,
        "line_end": line_end,
    }


def _make_observation(
    *,
    kind: str,
    source: dict[str, Any],
    fact: dict[str, Any],
    capture_method: str,
    captured_at: str,
    snapshot_commit: str,
    git_object: str,
) -> dict[str, Any]:
    identity = {
        "kind": kind,
        "source": source,
        "fact": fact,
        "capture_method": capture_method,
        "snapshot_commit": snapshot_commit,
        "git_object": git_object,
    }
    return {
        "observation_id": f"O-{hash_json(identity)[:24]}",
        "kind": kind,
        "source": source,
        "fact": fact,
        "capture_method": capture_method,
        "captured_at": captured_at,
        "snapshot_commit": snapshot_commit,
        "integrity": {
            "status": "source_bound",
            "algorithm": "sha256",
            "git_object": git_object,
        },
        "authority_scope": "observation_only",
        "interpretation": "none",
    }


def _ci_fact_type(provider: str, context: list[str], key: str, value: str) -> str:
    if provider == "github_actions":
        if key == "on" and not context:
            return "trigger_declaration"
        if context and context[0] == "on":
            return "trigger"
        if context == ["jobs"] and not value:
            return "job"
        if key == "continue-on-error":
            return "continue_on_error"
        if key in {"if", "needs", "runs-on", "uses", "run"}:
            return "execution_attribute"
    if key == "allow_failure":
        return "continue_on_error"
    return "configuration_key"


def _ci_observations(
    *,
    path: str,
    content: bytes,
    text: str,
    provider: str,
    captured_at: str,
    commit: str,
    git_object: str,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _YAML_KEY_RE.match(line)
        if not match or line.lstrip().startswith("#"):
            continue
        indent_text = match.group("indent").replace("\t", "    ")
        indent = len(indent_text)
        key = match.group("key")
        value = match.group("value").strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        context = [item[1] for item in stack]
        fact = {
            "provider": provider,
            "fact_type": _ci_fact_type(provider, context, key, value),
            "yaml_path": [*context, key],
            "key": key,
            "value": value,
            "indent": indent,
        }
        observations.append(
            _make_observation(
                kind="ci_workflow_fact",
                source=_source(path, content, line_number, line_number),
                fact=fact,
                capture_method="deterministic_yaml_line_scan_v1",
                captured_at=captured_at,
                snapshot_commit=commit,
                git_object=git_object,
            )
        )
        if not value:
            stack.append((indent, key))
    return observations


def _resolve_inputs(
    worktree: str | os.PathLike[str] | Mapping[str, Any],
    snapshot: Mapping[str, Any] | str | os.PathLike[str] | None,
) -> tuple[Path, dict[str, Any]]:
    # Support both observe_repository(worktree, snapshot) and the convenient
    # observe_repository(snapshot, worktree) without weakening validation.
    if isinstance(worktree, Mapping):
        metadata = dict(worktree)
        if snapshot is None:
            raw_root = metadata.get("repository_path")
        elif isinstance(snapshot, Mapping):
            raise UsageError("Only one snapshot mapping may be supplied.")
        else:
            raw_root = snapshot
    else:
        raw_root = worktree
        if snapshot is None:
            metadata = capture_snapshot(raw_root)
        elif isinstance(snapshot, Mapping):
            metadata = dict(snapshot)
        else:
            raise UsageError("snapshot must be a mapping when worktree is a path.")

    if raw_root is None:
        raise UsageError("A worktree path is required to read Git objects.")
    root = repository_root(raw_root)
    return root, metadata


def observe_repository(
    worktree: str | os.PathLike[str] | Mapping[str, Any],
    snapshot: Mapping[str, Any] | str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Return deterministic observations bound to one immutable commit.

    The first two arguments may be supplied in either ``(worktree, snapshot)`` or
    ``(snapshot, worktree)`` order.  Git blobs are read from the object database;
    untracked files and mutable working-tree bytes are never treated as snapshot
    evidence.
    """

    root, metadata = _resolve_inputs(worktree, snapshot)
    raw_commit = metadata.get("commit")
    if not isinstance(raw_commit, str):
        raise UsageError("Snapshot is missing a commit object ID.")
    commit = resolve_commit(root, raw_commit)
    if commit != raw_commit.lower():
        raise IntegrityError("Snapshot commit must already be a full immutable object ID.")

    actual_tree = _run_git(root, ["rev-parse", f"{commit}^{{tree}}"]).stdout.decode("ascii").strip()
    expected_tree = metadata.get("tree")
    if expected_tree is not None and expected_tree != actual_tree:
        raise IntegrityError(
            "Snapshot tree does not match its commit.",
            details={"expected": expected_tree, "actual": actual_tree},
        )

    captured_at = metadata.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at:
        captured_at = (
            _run_git(root, ["show", "-s", "--format=%cI", commit])
            .stdout.decode("utf-8", errors="replace")
            .strip()
        )

    observations: list[dict[str, Any]] = []
    for mode, object_type, object_id, path in _tree_entries(root, commit):
        if object_type == "blob":
            content = _git_blob(root, object_id)
        elif mode == "160000" and object_type == "commit":
            content = object_id.encode("ascii")
        else:
            continue

        line_end = _line_count(content)
        if mode == "160000":
            entry_type = "submodule"
        elif mode == "120000":
            entry_type = "symlink"
        else:
            entry_type = "file"
        structure_fact: dict[str, Any] = {
            "path": path,
            "entry_type": entry_type,
            "git_mode": mode,
            "git_object": object_id,
            "size_bytes": len(content),
        }
        observations.append(
            _make_observation(
                kind="repository_structure",
                source=_source(path, content, 1, line_end),
                fact=structure_fact,
                capture_method="git_ls_tree+git_cat_file",
                captured_at=captured_at,
                snapshot_commit=commit,
                git_object=object_id,
            )
        )

        if object_type != "blob":
            continue
        text = _decode_text(content)
        if text is None:
            continue

        is_documentation, document_role = _is_documentation(path)
        if is_documentation:
            for line_number, line in enumerate(text.splitlines(), start=1):
                excerpt = line.strip()
                if not excerpt:
                    continue
                observations.append(
                    _make_observation(
                        kind="documentation_claim_source",
                        source=_source(path, content, line_number, line_number),
                        fact={
                            "document_role": document_role,
                            "text": excerpt,
                            "assessment": "unassessed_source_text",
                        },
                        capture_method="deterministic_nonempty_line_scan_v1",
                        captured_at=captured_at,
                        snapshot_commit=commit,
                        git_object=object_id,
                    )
                )

        is_ci, provider = _is_ci_workflow(path)
        if is_ci:
            observations.extend(
                _ci_observations(
                    path=path,
                    content=content,
                    text=text,
                    provider=provider,
                    captured_at=captured_at,
                    commit=commit,
                    git_object=object_id,
                )
            )

        if _is_test_path(path):
            observations.append(
                _make_observation(
                    kind="test_path",
                    source=_source(path, content, 1, line_end),
                    fact={"path": path, "classification": "test_path"},
                    capture_method="deterministic_path_rule_v1",
                    captured_at=captured_at,
                    snapshot_commit=commit,
                    git_object=object_id,
                )
            )

        if _is_probably_text(path):
            for line_number, line in enumerate(text.splitlines(), start=1):
                for category, pattern in _SIGNAL_PATTERNS:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    observations.append(
                        _make_observation(
                            kind="control_signal",
                            source=_source(path, content, line_number, line_number),
                            fact={
                                "category": category,
                                "matched_text": match.group(0),
                                "line_text": line.strip(),
                                "assessment": "signal_only",
                            },
                            capture_method="deterministic_signal_scan_v1",
                            captured_at=captured_at,
                            snapshot_commit=commit,
                            git_object=object_id,
                        )
                    )

    return sorted(
        observations,
        key=lambda item: (
            item["source"]["path"].encode("utf-8", errors="surrogateescape"),
            item["source"]["line_start"],
            item["kind"],
            item["observation_id"],
        ),
    )


def collect_observations(
    snapshot: Mapping[str, Any],
    worktree: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Explicit snapshot-first wrapper around :func:`observe_repository`."""

    return observe_repository(snapshot, worktree)


__all__ = ["collect_observations", "observe_repository"]
