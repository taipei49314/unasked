from __future__ import annotations

from typing import Any


def classify_outcome(assertions: list[dict[str, Any]], executions: list[dict[str, Any]]) -> str:
    """Evaluate only frozen, exact-value assertions over recorded command facts."""

    by_command = {execution["command_id"]: execution for execution in executions}
    results: dict[str, list[bool]] = {"SUPPORTS": [], "FALSIFIES": []}
    for assertion in assertions:
        execution = by_command.get(assertion["command_id"])
        if execution is None:
            results[assertion["classification"]].append(False)
            continue
        field = assertion["field"]
        if field == "EXIT_CODE":
            actual: Any = execution["exit_code"]
        elif field == "STDOUT_SHA256":
            actual = execution["stdout_ref"]["sha256"]
        elif field == "STDERR_SHA256":
            actual = execution["stderr_ref"]["sha256"]
        else:
            actual = execution.get("diff_ref", {}).get("sha256")
        results[assertion["classification"]].append(actual == assertion["expected"])

    support = bool(results["SUPPORTS"]) and all(results["SUPPORTS"])
    falsify = bool(results["FALSIFIES"]) and all(results["FALSIFIES"])
    if support == falsify:
        return "INCONCLUSIVE"
    return "SUPPORTS" if support else "FALSIFIES"


__all__ = ["classify_outcome"]
