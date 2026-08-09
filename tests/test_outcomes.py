from __future__ import annotations

from unasked.outcomes import classify_outcome


def _execution(*, exit_code: int, stdout: str) -> dict:
    return {
        "command_id": "CMD-1",
        "exit_code": exit_code,
        "stdout_ref": {"sha256": stdout},
        "stderr_ref": {"sha256": "0" * 64},
    }


def _assertion(identifier: str, expected: str, classification: str) -> dict:
    return {
        "assertion_id": identifier,
        "command_id": "CMD-1",
        "field": "STDOUT_SHA256",
        "operator": "EQUALS",
        "expected": expected,
        "classification": classification,
    }


def test_exact_frozen_assertions_classify_support_and_falsification() -> None:
    support_hash = "a" * 64
    falsify_hash = "b" * 64
    assertions = [
        _assertion("A-SUPPORT", support_hash, "SUPPORTS"),
        _assertion("A-FALSIFY", falsify_hash, "FALSIFIES"),
    ]
    assert classify_outcome(assertions, [_execution(exit_code=0, stdout=support_hash)]) == (
        "SUPPORTS"
    )
    assert classify_outcome(assertions, [_execution(exit_code=0, stdout=falsify_hash)]) == (
        "FALSIFIES"
    )


def test_ambiguous_or_unmatched_assertions_are_inconclusive() -> None:
    same_hash = "a" * 64
    assertions = [
        _assertion("A-SUPPORT", same_hash, "SUPPORTS"),
        _assertion("A-FALSIFY", same_hash, "FALSIFIES"),
    ]
    assert classify_outcome(assertions, [_execution(exit_code=0, stdout=same_hash)]) == (
        "INCONCLUSIVE"
    )
    assert classify_outcome(assertions, [_execution(exit_code=0, stdout="c" * 64)]) == (
        "INCONCLUSIVE"
    )
