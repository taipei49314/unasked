from __future__ import annotations

import base64
import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_attestations import _envelope, _policy
from test_m0_v2 import _make_case

from unasked.errors import IntegrityError, UnaskedError, UsageError
from unasked.ledger import EventLedger
from unasked.trials import certify_m0_v2
from unasked.util import canonical_json, hash_json, sha256_bytes

EVALUATION_TYPE = "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4"
CERTIFICATION_TYPE = "https://schemas.unasked.dev/attestations/m0-certification/v0.4"


def _payload(envelope_bytes: bytes) -> dict:
    envelope = json.loads(envelope_bytes)
    return json.loads(base64.b64decode(envelope["payload"]))


def _matrix_bytes(matrix: dict) -> bytes:
    matrix = deepcopy(matrix)
    matrix["matrix_sha256"] = hash_json(
        {name: value for name, value in matrix.items() if name != "matrix_sha256"}
    )
    return canonical_json(matrix)


@pytest.mark.parametrize(
    "unsafe_path",
    ["../escaped-result.json", "C:/escaped-result.json", "/escaped-result.json"],
)
def test_matrix_rejects_unsafe_evidence_locators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_path: str,
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    matrix = deepcopy(case.matrix)
    matrix["entries"][0]["result"]["path"] = unsafe_path

    with pytest.raises(UsageError, match="safe relative"):
        certify_m0_v2(**{**case.kwargs, "run_matrix_bytes": _matrix_bytes(matrix)})


def test_matrix_rejects_symlinked_evidence_and_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    entry = case.matrix["entries"][0]
    outside = tmp_path / "outside-result.json"
    outside.write_bytes(b"{}")
    linked_result = case.base / "linked-result.json"
    linked_workspace = case.base / "linked-workspace"
    try:
        linked_result.symlink_to(outside)
        linked_workspace.symlink_to(
            (case.base / entry["workspace"]).resolve(), target_is_directory=True
        )
    except OSError as exc:
        pytest.skip(f"This Windows host cannot create test symlinks: {exc}")

    for field, locator, digest in (
        ("result", "linked-result.json", sha256_bytes(outside.read_bytes())),
        ("workspace", "linked-workspace", None),
    ):
        matrix = deepcopy(case.matrix)
        if field == "workspace":
            matrix["entries"][0][field] = locator
        else:
            matrix["entries"][0][field] = {"path": locator, "sha256": digest}
        with pytest.raises(UsageError, match="links|reparse"):
            certify_m0_v2(**{**case.kwargs, "run_matrix_bytes": _matrix_bytes(matrix)})


@pytest.mark.parametrize("duplicate", ["pair", "run", "workspace"])
def test_matrix_rejects_duplicate_pair_run_and_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    duplicate: str,
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    matrix = deepcopy(case.matrix)
    first, second = matrix["entries"][:2]
    if duplicate == "pair":
        second["variant"] = first["variant"]
        second["case_id"] = first["case_id"]
    elif duplicate == "run":
        second["run_id"] = first["run_id"]
    else:
        second["workspace"] = first["workspace"]

    with pytest.raises(IntegrityError, match="unique 5x7"):
        certify_m0_v2(**{**case.kwargs, "run_matrix_bytes": _matrix_bytes(matrix)})


def test_exact_evidence_index_byte_substitution_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)

    with pytest.raises(UnaskedError):
        certify_m0_v2(
            **{**case.kwargs, "evidence_index_bytes": case.kwargs["evidence_index_bytes"] + b"\n"}
        )


def test_old_valid_final_checkpoint_cannot_hide_a_new_ledger_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    matrix = deepcopy(case.matrix)
    entry = matrix["entries"][0]
    ledger_path = case.base / entry["ledger"]["path"]
    EventLedger(ledger_path, run_id=entry["run_id"]).append("POST_CHECKPOINT", {"new": True})
    entry["ledger"]["sha256"] = sha256_bytes(ledger_path.read_bytes())

    with pytest.raises(IntegrityError):
        certify_m0_v2(**{**case.kwargs, "run_matrix_bytes": _matrix_bytes(matrix)})


def test_authenticated_certificate_set_rejects_binding_omission_and_extra_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = _make_case(tmp_path, monkeypatch, production=True)
    omitted = deepcopy(production.matrix)
    verified_entry = next(item for item in omitted["entries"] if item["certificate_bindings"])
    verified_entry["certificate_bindings"] = []
    with pytest.raises(IntegrityError):
        certify_m0_v2(**{**production.kwargs, "run_matrix_bytes": _matrix_bytes(omitted)})

    shadow = _make_case(tmp_path / "shadow", monkeypatch, production=False)
    extra = deepcopy(shadow.matrix)
    entry = extra["entries"][0]
    marker = shadow.base / entry["workspace"] / "discoveries" / "UNLISTED"
    marker.mkdir(parents=True)
    (marker / "authorization-commit.json").write_bytes(b"{}")
    with pytest.raises(IntegrityError):
        certify_m0_v2(**{**shadow.kwargs, "run_matrix_bytes": _matrix_bytes(extra)})


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("observed", "trusted_verified_positives", 4),
        ("observed", "claimed_verified_total", 4),
        ("gates", "actor_identities_authenticated", False),
        ("gates", "certificate_graphs_valid", False),
        ("gates", "inputs_immutable", False),
    ],
)
def test_signed_evaluation_cannot_launder_recomputed_counts_or_producer_booleans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    field: str,
    value: object,
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=True)
    predicate = _payload(case.kwargs["trial_evaluation_envelope_bytes"])["predicate"]
    predicate[section][field] = value
    _, _, keys = _policy()
    forged = _envelope(
        EVALUATION_TYPE,
        predicate,
        case.kwargs["report_bytes"],
        keys["TRIAL_EVALUATOR"],
    )

    with pytest.raises(UnaskedError):
        certify_m0_v2(**{**case.kwargs, "trial_evaluation_envelope_bytes": forged})


def test_shadow_policy_cannot_launder_a_signed_m0_demonstrated_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(tmp_path, monkeypatch, production=False)
    predicate = _payload(case.kwargs["certification_envelope_bytes"])["predicate"]
    predicate["decision"] = "M0_DEMONSTRATED"
    predicate["claim"] = (
        "Demonstrated blind discovery of reproducible discrepancies on a sealed evaluation set."
    )
    _, _, keys = _policy()
    forged = _envelope(
        CERTIFICATION_TYPE,
        predicate,
        case.kwargs["trial_evaluation_envelope_bytes"],
        keys["M0_CERTIFIER"],
    )

    with pytest.raises(IntegrityError, match="M0_DEMONSTRATED"):
        certify_m0_v2(**{**case.kwargs, "certification_envelope_bytes": forged})
