from __future__ import annotations

import ast
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import unasked.ledger as ledger_module
from unasked.locking import exclusive_file_lock, file_lock_held_by_current_thread
from unasked.project import Project

_SOURCE_ROOT = Path(__file__).parents[1] / "src" / "unasked"


def _new_project_with_run(tmp_path: Path) -> tuple[Project, str]:
    project = Project.create(tmp_path / "workspace")
    run_id = "run-redteam-lock"
    (project.runs_root / run_id).mkdir()
    return project, run_id


def _wait_for(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists(), f"timed out waiting for {path}"


def _function_nodes(tree: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _call_name(call: ast.Call) -> str | None:
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _decorators(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Name):
            names.add(decorator.id)
        elif isinstance(decorator, ast.Attribute):
            names.add(decorator.attr)
        elif isinstance(decorator, ast.Call):
            name = _call_name(decorator)
            if name is not None:
                names.add(name)
    return names


def test_same_thread_authority_style_outer_lock_can_call_project_mutator_without_deadlock(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    code = "\n".join(
        (
            "from pathlib import Path",
            "from unasked.project import Project",
            "workspace = Path(__import__('sys').argv[1])",
            "project = Project.create(workspace)",
            "run_id = 'run-nested-lock'",
            "(project.runs_root / run_id).mkdir()",
            "with project.mutation(run_id):",
            "    project.assert_mutation_locked(run_id)",
            "    project.append_event(run_id, 'REDTEAM_NESTED_LOCK')",
        )
    )

    completed = subprocess.run(
        [sys.executable, "-c", code, str(workspace)],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


def test_common_mutation_lock_serializes_threads(tmp_path: Path) -> None:
    project, run_id = _new_project_with_run(tmp_path)
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with project.mutation(run_id):
            first_entered.set()
            assert release_first.wait(timeout=5)

    def second() -> None:
        assert first_entered.wait(timeout=5)
        with project.mutation(run_id):
            second_entered.set()

    first_thread = threading.Thread(target=first, daemon=True)
    second_thread = threading.Thread(target=second, daemon=True)
    first_thread.start()
    second_thread.start()
    assert first_entered.wait(timeout=5)
    assert second_entered.wait(timeout=0.1) is False
    release_first.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)

    assert first_thread.is_alive() is False
    assert second_thread.is_alive() is False
    assert second_entered.is_set()


def test_common_mutation_lock_serializes_processes(tmp_path: Path) -> None:
    lock_path = tmp_path / "run" / ".mutation.lock"
    ready_path = tmp_path / "child-ready"
    acquired_path = tmp_path / "child-acquired"
    code = "\n".join(
        (
            "from pathlib import Path",
            "from unasked.locking import exclusive_file_lock",
            "import sys",
            "lock_path, ready_path, acquired_path = map(Path, sys.argv[1:])",
            "ready_path.write_text('ready', encoding='utf-8')",
            "with exclusive_file_lock(lock_path):",
            "    acquired_path.write_text('acquired', encoding='utf-8')",
        )
    )

    with exclusive_file_lock(lock_path):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                code,
                str(lock_path),
                str(ready_path),
                str(acquired_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for(ready_path)
        assert acquired_path.exists() is False
        assert child.poll() is None

    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, f"stdout={stdout!r}\nstderr={stderr!r}"
    assert acquired_path.read_text(encoding="utf-8") == "acquired"


def test_project_mutator_acquires_common_lock_before_ledger_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, run_id = _new_project_with_run(tmp_path)
    original_ledger_lock = ledger_module.exclusive_file_lock
    ledger_lock_observations: list[bool] = []

    @contextmanager
    def checked_ledger_lock(path: str | Path) -> Iterator[None]:
        ledger_lock_observations.append(
            file_lock_held_by_current_thread(project.mutation_lock_path(run_id))
        )
        with original_ledger_lock(path):
            yield

    monkeypatch.setattr(ledger_module, "exclusive_file_lock", checked_ledger_lock)

    project.append_event(run_id, "REDTEAM_LOCK_ORDER")
    with project.mutation(run_id):
        project.append_event(run_id, "REDTEAM_AUTHORITY_FINALIZE")

    assert ledger_lock_observations == [True, True]
    assert project.verify_ledger(run_id)["valid"] is True


def test_source_has_no_direct_ledger_append_bypass_outside_project_gateway() -> None:
    direct_calls: set[tuple[str, str]] = set()

    for path in _SOURCE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for function in _function_nodes(tree):
            tainted_names: set[str] = set()
            for node in ast.walk(function):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    if isinstance(value, ast.Call) and _call_name(value) in {
                        "EventLedger",
                        "ledger",
                    }:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        tainted_names.update(
                            target.id for target in targets if isinstance(target, ast.Name)
                        )
            for node in ast.walk(function):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "append":
                    continue
                receiver = node.func.value
                direct = (isinstance(receiver, ast.Call) and _call_name(receiver) == "ledger") or (
                    isinstance(receiver, ast.Name) and receiver.id in tainted_names
                )
                if direct:
                    direct_calls.add((path.name, function.name))

    assert direct_calls == {("project.py", "append_event")}


def test_append_jsonl_calls_are_confined_to_common_lock_scopes() -> None:
    call_sites: set[tuple[str, str]] = set()
    functions_by_file: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}

    for path in _SOURCE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        functions = {function.name: function for function in _function_nodes(tree)}
        functions_by_file[path.name] = functions
        for function in functions.values():
            if any(
                isinstance(node, ast.Call) and _call_name(node) == "append_jsonl"
                for node in ast.walk(function)
            ):
                call_sites.add((path.name, function.name))

    assert call_sites == {
        ("explorer.py", "run"),
        ("project.py", "_transition"),
        ("project.py", "append_candidate_record"),
        ("project.py", "append_record"),
        ("project.py", "create_candidate"),
    }
    for name in ("append_candidate_record", "append_record", "create_candidate"):
        assert "_run_mutation" in _decorators(functions_by_file["project.py"][name])

    transition_callers = {
        function.name
        for function in functions_by_file["project.py"].values()
        if any(
            isinstance(node, ast.Call) and _call_name(node) == "_transition"
            for node in ast.walk(function)
        )
    }
    assert transition_callers == {
        "authorize_verified",
        "create_candidate",
        "transition_candidate",
    }
    for name in transition_callers:
        assert "_run_mutation" in _decorators(functions_by_file["project.py"][name])

    explorer_run = functions_by_file["explorer.py"]["run"]
    assert any(
        isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call) and _call_name(item.context_expr) == "mutation"
            for item in node.items
        )
        and any(
            isinstance(child, ast.Call) and _call_name(child) == "append_jsonl"
            for child in ast.walk(node)
        )
        for node in ast.walk(explorer_run)
    )


def test_all_run_evidence_project_public_mutators_take_the_common_lock() -> None:
    tree = ast.parse(
        (_SOURCE_ROOT / "project.py").read_text(encoding="utf-8"),
        filename="project.py",
    )
    functions = {function.name: function for function in _function_nodes(tree)}
    decorated_mutators = {
        "append_candidate_record",
        "append_event",
        "append_record",
        "authorize_verified",
        "create_candidate",
        "transition_candidate",
        "write_candidate_artifact",
        "write_run_artifact",
    }

    for name in decorated_mutators:
        assert "_run_mutation" in _decorators(functions[name]), name

    create_run = functions["create_run"]
    mutation_scopes = [
        node
        for node in ast.walk(create_run)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call) and _call_name(item.context_expr) == "mutation"
            for item in node.items
        )
    ]
    assert len(mutation_scopes) == 1
    protected_calls = {
        _call_name(node) for node in ast.walk(mutation_scopes[0]) if isinstance(node, ast.Call)
    }
    assert {"append_event", "upsert_run", "_write_once"}.issubset(protected_calls)
