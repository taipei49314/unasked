from __future__ import annotations

import pytest

from unasked.errors import PolicyError
from unasked.policy import (
    Actor,
    Capability,
    State,
    assert_p0_claim_allowed,
    require_capability,
    require_distinct_actors,
    require_transition,
)


def test_happy_path_transitions_are_legal() -> None:
    path = [
        State.SIGNAL,
        State.CANDIDATE,
        State.HYPOTHESIZED,
        State.TESTABLE,
        State.SUPPORTED,
        State.REPRODUCED,
        State.VERIFIED,
    ]
    for current, target in zip(path, path[1:], strict=False):
        require_transition(current, target)


def test_explorer_cannot_authorize() -> None:
    with pytest.raises(PolicyError, match="lacks required capability"):
        require_capability(Actor("explorer-1", "explorer"), Capability.AUTHORIZE_VERDICT)


def test_authority_must_be_distinct() -> None:
    with pytest.raises(PolicyError, match="must be separate"):
        require_distinct_actors("same", "same")


def test_illegal_transition_is_rejected() -> None:
    with pytest.raises(PolicyError, match="Illegal"):
        require_transition(State.CANDIDATE, State.VERIFIED)


def test_forbidden_p0_marketing_claim_is_rejected() -> None:
    with pytest.raises(PolicyError, match="not authorized"):
        assert_p0_claim_allowed("The product is an AUTONOMOUS discovery agent")
