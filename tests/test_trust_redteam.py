from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unasked.errors import IntegrityError, UsageError
from unasked.schemas import SchemaValidationError
from unasked.trust import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    PREDICATE_ROLES,
    TrustedEd25519Key,
    dsse_pae,
    load_trust_policy,
    verify_dsse_json_envelope,
    verify_dsse_statement,
)
from unasked.util import canonical_json, sha256_bytes

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_HASH = "a" * 64
_AUTHORITY_TYPE = "https://schemas.unasked.dev/attestations/authority-authorization/v0.4"
_CUSTODY_TYPE = "https://schemas.unasked.dev/attestations/custody/v0.4"
_TRIAL_TYPE = "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4"
_VARIANTS = (
    "deterministic-detectors-only",
    "read-only-llm-reviewer",
    "llm-tools-no-experiment-gate",
    "experiment-loop-without-falsifier",
    "full-evidence-gated-system",
)


def _private(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _trusted(private_key: Ed25519PrivateKey, keyid: str | None = None) -> TrustedEd25519Key:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return TrustedEd25519Key(public_key, keyid)


def _encoded(value: bytes, *, urlsafe: bool) -> str:
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(value).decode("ascii")


def _envelope(
    payload: bytes,
    private_key: Ed25519PrivateKey,
    *,
    payload_type: str = _PAYLOAD_TYPE,
    keyid: str | None = "trusted",
    urlsafe: bool = False,
    envelope_extra: dict | None = None,
    signature_extra: dict | None = None,
) -> bytes:
    signature_entry = {
        "sig": _encoded(private_key.sign(dsse_pae(payload_type, payload)), urlsafe=urlsafe),
    }
    if keyid is not None:
        signature_entry["keyid"] = keyid
    if signature_extra:
        signature_entry.update(signature_extra)
    document = {
        "payloadType": payload_type,
        "payload": _encoded(payload, urlsafe=urlsafe),
        "signatures": [signature_entry],
    }
    if envelope_extra:
        document.update(envelope_extra)
    return canonical_json(document)


def _policy_document(*, mode: str = "PRODUCTION") -> tuple[dict, dict[str, Ed25519PrivateKey]]:
    roles = sorted({role for role, _ in PREDICATE_ROLES.values()})
    private_keys = {role: _private(40 + index) for index, role in enumerate(roles)}
    document = {
        "schema_version": "0.4.0",
        "policy_id": "policy-redteam",
        "mode": mode,
        "issued_at": "2025-01-01T00:00:00Z",
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
        "algorithm": "Ed25519",
        "dsse_payload_type": DSSE_PAYLOAD_TYPE,
        "statement_type": IN_TOTO_STATEMENT_TYPE,
        "keys": [
            {
                "key_id": f"key-{role.lower().replace('_', '-')}",
                "actor_id": f"actor-{role.lower().replace('_', '-')}",
                "role": role,
                "status": "ACTIVE",
                "public_key_base64": base64.b64encode(
                    _trusted(private_keys[role]).public_key
                ).decode("ascii"),
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2030-01-01T00:00:00Z",
            }
            for role in roles
        ],
        "thresholds": [{"role": role, "minimum_signatures": 1} for role in roles],
        "predicate_roles": [
            {"predicate_type": predicate_type, "role": role}
            for predicate_type, (role, _) in PREDICATE_ROLES.items()
        ],
        "separation": {
            "unique_public_keys": True,
            "one_role_per_key": True,
            "distinct_actor_ids_across_roles": True,
        },
    }
    return document, private_keys


def _load_policy_document(document: dict):
    policy_bytes = canonical_json(document)
    return load_trust_policy(
        policy_bytes,
        expected_sha256=sha256_bytes(policy_bytes),
        now="2026-01-01T00:00:00Z",
    )


def _key_entry(document: dict, role: str) -> dict:
    return next(item for item in document["keys"] if item["role"] == role)


def _signed_statement(
    predicate_type: str,
    predicate: dict,
    private_keys: list[Ed25519PrivateKey],
    *,
    statement_extra: dict | None = None,
) -> bytes:
    statement = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": "opaque-subject", "digest": {"sha256": _HASH}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    if statement_extra:
        statement.update(statement_extra)
    payload = canonical_json(statement)
    signatures = [
        {
            "sig": base64.b64encode(private_key.sign(dsse_pae(DSSE_PAYLOAD_TYPE, payload))).decode(
                "ascii"
            )
        }
        for private_key in private_keys
    ]
    return canonical_json(
        {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": signatures,
        }
    )


def _authority_predicate(policy_sha256: str, actor_id: str, *, issued_at: str) -> dict:
    return {
        "schema_version": "0.4.0",
        "predicate_id": "authority-redteam",
        "issued_at": issued_at,
        "issuer_actor_id": actor_id,
        "trust_policy_sha256": policy_sha256,
        "run_id": "run-redteam",
        "candidate_id": "candidate-redteam",
        "target_snapshot_hash": _HASH,
        "protocol_hash": _HASH,
        "knowledge_boundary_hash": _HASH,
        "context_manifest_hash": _HASH,
        "evidence_bundle_hash": _HASH,
        "ledger_checkpoint_envelope_sha256": _HASH,
        "custody_envelope_sha256": _HASH,
        "isolation_envelope_sha256": _HASH,
        "prepared_graph_sha256": _HASH,
        "decision": "AUTHORIZE_VERIFIED",
        "authorized_state": "VERIFIED",
        "expires_at": "2030-01-01T00:00:00Z",
    }


def _custody_predicate(policy_sha256: str, actor_id: str) -> dict:
    return {
        "schema_version": "0.4.0",
        "predicate_id": "custody-redteam",
        "issued_at": "2026-01-03T00:00:00Z",
        "issuer_actor_id": actor_id,
        "trust_policy_sha256": policy_sha256,
        "suite_id": "suite-redteam",
        "manifest_sha256": _HASH,
        "case_commitment_sha256": _HASH,
        "sealed_at": "2026-01-01T00:00:00Z",
        "explorer_development_started_at": "2026-01-02T00:00:00Z",
        "independent_custody": True,
        "sealed_before_explorer": True,
        "hidden_case_count": 7,
        "positive_case_count": 5,
        "control_case_count": 2,
        "explorer_ground_truth_access": False,
        "evaluator_access": False,
        "directional_steering": False,
    }


def _verify_policy_statement(
    policy,
    envelope: bytes,
    predicate_type: str,
):
    return verify_dsse_statement(
        envelope,
        expected_predicate_type=predicate_type,
        trusted_keys=policy.keys_for(predicate_type),
        threshold=policy.threshold_for(predicate_type),
        predicate_schema=PREDICATE_ROLES[predicate_type][1],
    )


def _trial_predicate(policy_sha256: str, actor_id: str) -> dict:
    run_bindings = [
        {
            "variant": variant,
            "case_id": f"case-{case_number}",
            "run_id": f"run-{case_number}-{variant}",
            "target_snapshot_hash": _HASH,
            "result_sha256": _HASH,
            "isolation_envelope_sha256": _HASH,
            "ledger_checkpoint_envelope_sha256": _HASH,
            "evidence_index_entry_sha256": _HASH,
            "certificate_set_sha256": _HASH,
        }
        for case_number in range(1, 8)
        for variant in _VARIANTS
    ]
    return {
        "schema_version": "0.4.0",
        "predicate_id": "trial-redteam",
        "issued_at": "2026-01-01T00:00:00Z",
        "issuer_actor_id": actor_id,
        "trust_policy_sha256": policy_sha256,
        "suite_id": "suite-redteam",
        "manifest_sha256": _HASH,
        "protocol_hash": _HASH,
        "custody_envelope_sha256": _HASH,
        "report_sha256": _HASH,
        "evidence_index_sha256": _HASH,
        "audit_sha256": _HASH,
        "run_matrix_sha256": _HASH,
        "run_count": 35,
        "variant_count": 5,
        "case_count": 7,
        "run_bindings": run_bindings,
        "thresholds": {
            "positive_cases_required": 3,
            "positive_cases_total": 5,
            "control_false_verified_max": 0,
            "clean_replay_rate_required": "1.000000",
            "run_count_required": 35,
            "variant_count_required": 5,
            "case_count_required": 7,
        },
        "observed": {
            "trusted_verified_positives": 3,
            "false_verified_controls": 0,
            "false_verified_claims": 0,
            "claimed_verified_total": 3,
            "clean_replay_verified": 3,
            "context_provenance_complete": True,
            "target_snapshot_immutable": True,
            "hidden_inputs_immutable": True,
            "scoring_policy_immutable": True,
        },
        "gates": {
            "matrix_complete": True,
            "independent_custody": True,
            "sealed_before_explorer": True,
            "actor_identities_authenticated": True,
            "isolation_attestations_authenticated": True,
            "ledger_checkpoints_authenticated": True,
            "certificate_graphs_valid": True,
            "positive_threshold_met": True,
            "control_threshold_met": True,
            "clean_replay_complete": True,
            "context_provenance_complete": True,
            "inputs_immutable": True,
        },
        "status": "THRESHOLDS_MET",
    }


def test_cross_payload_type_cannot_replay_one_signature_under_another_type() -> None:
    signer = _private(21)
    trusted = [_trusted(signer, "trusted")]
    payload = b'{"claim":"same bytes"}'
    envelope = _envelope(payload, signer)
    document = __import__("json").loads(envelope)
    document["payloadType"] = "application/example+json"

    with pytest.raises(IntegrityError, match="threshold"):
        verify_dsse_json_envelope(
            canonical_json(document),
            expected_payload_type="application/example+json",
            trusted_keys=trusted,
        )
    with pytest.raises(IntegrityError, match="payloadType"):
        verify_dsse_json_envelope(
            canonical_json(document),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
        )


def test_duplicate_json_keys_fail_in_both_envelope_and_verified_payload() -> None:
    signer = _private(22)
    trusted = [_trusted(signer, "trusted")]
    duplicate_envelope = (
        b'{"payloadType":"application/vnd.in-toto+json",'
        b'"payload":"e30=","payload":"e30=","signatures":[]}'
    )
    duplicate_payload = b'{"claim":false,"claim":true}'

    with pytest.raises(UsageError, match="strict UTF-8 JSON"):
        verify_dsse_json_envelope(
            duplicate_envelope,
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
        )
    with pytest.raises(UsageError, match="strict UTF-8 JSON"):
        verify_dsse_json_envelope(
            _envelope(duplicate_payload, signer),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
        )


def test_signed_invalid_utf8_is_not_accepted_as_json_evidence() -> None:
    signer = _private(23)

    with pytest.raises(UsageError, match="strict UTF-8 JSON"):
        verify_dsse_json_envelope(
            _envelope(b'{"value":"\xff"}', signer),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[_trusted(signer, "trusted")],
        )


@pytest.mark.parametrize("urlsafe", [False, True])
def test_official_standard_and_urlsafe_base64_envelopes_verify(urlsafe: bool) -> None:
    signer = _private(24)
    payload = b'{"interop":"standard-or-url-safe"}'
    envelope = _envelope(payload, signer, urlsafe=urlsafe)

    assert verify_dsse_json_envelope(
        envelope,
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[_trusted(signer, "trusted")],
    ) == {"interop": "standard-or-url-safe"}

    if urlsafe:
        document = __import__("json").loads(envelope)
        assert "-" in document["signatures"][0]["sig"] or "_" in document["signatures"][0]["sig"]


def test_optional_keyid_and_unknown_transport_fields_do_not_pollute_predicate() -> None:
    signer = _private(25)
    envelope = _envelope(
        b'{"predicate":{"strict":"application-layer"}}',
        signer,
        keyid=None,
        envelope_extra={"futureEnvelopeField": {"must": "ignore"}},
        signature_extra={"futureSignatureField": ["must", "ignore"]},
    )

    assert verify_dsse_json_envelope(
        envelope,
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[_trusted(signer, "registry-hint")],
    ) == {"predicate": {"strict": "application-layer"}}


def test_zero_signatures_never_authenticates_payload() -> None:
    signer = _private(26)
    document = __import__("json").loads(_envelope(b"{}", signer))
    document["signatures"] = []

    with pytest.raises(UsageError, match="at least one signature"):
        verify_dsse_json_envelope(
            canonical_json(document),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[_trusted(signer, "trusted")],
        )


def test_same_raw_key_under_different_keyids_cannot_satisfy_two_key_threshold() -> None:
    signer = _private(27)
    independent = _private(28)
    payload = b"{}"
    signature = _encoded(signer.sign(dsse_pae(_PAYLOAD_TYPE, payload)), urlsafe=False)
    envelope = canonical_json(
        {
            "payloadType": _PAYLOAD_TYPE,
            "payload": _encoded(payload, urlsafe=False),
            "signatures": [
                {"keyid": "producer", "sig": signature},
                {"keyid": "witness", "sig": signature},
            ],
        }
    )

    with pytest.raises(IntegrityError, match="threshold"):
        verify_dsse_json_envelope(
            envelope,
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[
                _trusted(signer, "producer"),
                _trusted(signer, "witness"),
                _trusted(independent, "independent"),
            ],
            threshold=2,
        )


def test_invalid_extra_signature_does_not_count_toward_threshold() -> None:
    first = _private(29)
    second = _private(30)
    attacker = _private(31)
    payload = b"{}"
    envelope = __import__("json").loads(_envelope(payload, first, keyid="first"))
    envelope["signatures"].append(
        {
            "keyid": "second",
            "sig": _encoded(attacker.sign(dsse_pae(_PAYLOAD_TYPE, payload)), urlsafe=False),
        }
    )

    with pytest.raises(IntegrityError, match="threshold"):
        verify_dsse_json_envelope(
            canonical_json(envelope),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[_trusted(first, "first"), _trusted(second, "second")],
            threshold=2,
        )


def test_untrusted_signer_cannot_spoof_a_trusted_keyid() -> None:
    trusted_signer = _private(32)
    attacker = _private(33)

    with pytest.raises(IntegrityError, match="caller-trusted"):
        verify_dsse_json_envelope(
            _envelope(b"{}", attacker, keyid="trusted"),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[_trusted(trusted_signer, "trusted")],
        )


def test_one_valid_signature_is_still_below_a_two_key_threshold() -> None:
    first = _private(34)
    second = _private(35)

    with pytest.raises(IntegrityError, match="threshold"):
        verify_dsse_json_envelope(
            _envelope(b"{}", first, keyid="first"),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[_trusted(first, "first"), _trusted(second, "second")],
            threshold=2,
        )


def test_semantically_equal_payload_rewrite_is_not_the_verified_byte_string() -> None:
    signer = _private(36)
    trusted = [_trusted(signer, "trusted")]
    signed_payload = b'{"a":1, "b":2}'
    envelope = __import__("json").loads(_envelope(signed_payload, signer))

    assert verify_dsse_json_envelope(
        canonical_json(envelope),
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=trusted,
    ) == {"a": 1, "b": 2}

    envelope["payload"] = _encoded(b'{"a":1,"b":2}', urlsafe=False)
    with pytest.raises(IntegrityError, match="caller-trusted"):
        verify_dsse_json_envelope(
            canonical_json(envelope),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
        )


def test_policy_pin_is_over_exact_bytes_not_parsed_or_self_claimed_content() -> None:
    document, _ = _policy_document()
    canonical = canonical_json(document)
    whitespace_rewrite = b"\n" + canonical

    with pytest.raises(IntegrityError, match="exact-byte"):
        load_trust_policy(
            whitespace_rewrite,
            expected_sha256=sha256_bytes(canonical),
            now="2026-01-01T00:00:00Z",
        )
    with pytest.raises(IntegrityError, match="exact-byte"):
        load_trust_policy(
            canonical,
            expected_sha256=_HASH,
            now="2026-01-01T00:00:00Z",
        )
    with pytest.raises(UsageError, match="Expected trust policy SHA-256"):
        load_trust_policy(
            canonical,
            expected_sha256="",
            now="2026-01-01T00:00:00Z",
        )


@pytest.mark.parametrize("duplicate_kind", ["key_id", "raw_key"])
def test_production_policy_rejects_duplicate_key_identity(duplicate_kind: str) -> None:
    document, _ = _policy_document()
    authority = _key_entry(document, "DISCOVERY_AUTHORITY")
    custodian = _key_entry(document, "CUSTODIAN")
    if duplicate_kind == "key_id":
        custodian["key_id"] = authority["key_id"]
    else:
        custodian["public_key_base64"] = authority["public_key_base64"]

    with pytest.raises(IntegrityError, match="duplicate"):
        _load_policy_document(document)


def test_production_policy_rejects_one_actor_spanning_multiple_roles() -> None:
    document, _ = _policy_document()
    _key_entry(document, "CUSTODIAN")["actor_id"] = _key_entry(document, "DISCOVERY_AUTHORITY")[
        "actor_id"
    ]

    with pytest.raises(IntegrityError, match="actors may not span"):
        _load_policy_document(document)


def test_production_threshold_needs_distinct_actor_ids_even_with_distinct_keys() -> None:
    document, private_keys = _policy_document()
    role = "DISCOVERY_AUTHORITY"
    authority = _key_entry(document, role)
    second = _private(70)
    document["keys"].append(
        {
            **authority,
            "key_id": "key-authority-second",
            "public_key_base64": base64.b64encode(_trusted(second).public_key).decode("ascii"),
        }
    )
    next(item for item in document["thresholds"] if item["role"] == role)["minimum_signatures"] = 2

    with pytest.raises(IntegrityError, match="distinct configured signers"):
        _load_policy_document(document)

    assert role in private_keys


@pytest.mark.parametrize(
    ("status", "key_from", "key_until", "issued_at"),
    [
        ("REVOKED", "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ("ACTIVE", "2026-01-02T00:00:00Z", "2030-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ("ACTIVE", "2025-01-01T00:00:00Z", "2025-12-31T23:59:59Z", "2026-01-01T00:00:00Z"),
    ],
)
def test_revoked_not_yet_valid_and_expired_keys_cannot_satisfy_statement_threshold(
    status: str,
    key_from: str,
    key_until: str,
    issued_at: str,
) -> None:
    document, private_keys = _policy_document()
    role = "DISCOVERY_AUTHORITY"
    key = _key_entry(document, role)
    key.update(status=status, valid_from=key_from, valid_until=key_until)
    policy = _load_policy_document(document)
    predicate = _authority_predicate(policy.sha256, key["actor_id"], issued_at=issued_at)

    with pytest.raises(IntegrityError, match="active, time-valid"):
        _verify_policy_statement(
            policy,
            _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys[role]]),
            _AUTHORITY_TYPE,
        )


@pytest.mark.parametrize("issued_at", ["2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"])
def test_statement_issue_time_accepts_inclusive_key_validity_boundaries(issued_at: str) -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(policy.sha256, key["actor_id"], issued_at=issued_at)

    verified = _verify_policy_statement(
        policy,
        _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["DISCOVERY_AUTHORITY"]]),
        _AUTHORITY_TYPE,
    )

    assert verified.production_qualified is True


@pytest.mark.parametrize("issued_at", ["2024-12-31T23:59:59Z", "2030-01-01T00:00:01Z"])
def test_statement_issue_time_outside_pinned_policy_window_is_rejected(issued_at: str) -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(policy.sha256, key["actor_id"], issued_at=issued_at)

    with pytest.raises(IntegrityError, match="active, time-valid"):
        _verify_policy_statement(
            policy,
            _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["DISCOVERY_AUTHORITY"]]),
            _AUTHORITY_TYPE,
        )


def test_signed_predicate_cannot_self_claim_a_different_policy_hash() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(_HASH, key["actor_id"], issued_at="2026-01-01T00:00:00Z")

    with pytest.raises(IntegrityError, match="policy binding"):
        _verify_policy_statement(
            policy,
            _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["DISCOVERY_AUTHORITY"]]),
            _AUTHORITY_TYPE,
        )


def test_wrong_role_key_cannot_verify_predicate_even_with_valid_signature() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    predicate = _authority_predicate(
        policy.sha256,
        _key_entry(document, "CUSTODIAN")["actor_id"],
        issued_at="2026-01-01T00:00:00Z",
    )

    with pytest.raises(IntegrityError, match="threshold"):
        _verify_policy_statement(
            policy,
            _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["CUSTODIAN"]]),
            _AUTHORITY_TYPE,
        )


def test_predicate_type_and_schema_cannot_be_cross_wired() -> None:
    document, _ = _policy_document()
    policy = _load_policy_document(document)

    with pytest.raises(UsageError, match="canonical pair"):
        verify_dsse_statement(
            b"{}",
            expected_predicate_type=_AUTHORITY_TYPE,
            trusted_keys=policy.keys_for(_AUTHORITY_TYPE),
            threshold=1,
            predicate_schema="custody-attestation-predicate",
        )


@pytest.mark.parametrize(
    ("signed_predicate_type", "statement_extra", "message"),
    [
        (_AUTHORITY_TYPE, {"_type": "https://in-toto.io/Statement/v0.1"}, "statement type"),
        (_CUSTODY_TYPE, None, "predicate type"),
    ],
)
def test_wrong_signed_statement_or_predicate_type_is_rejected(
    signed_predicate_type: str,
    statement_extra: dict | None,
    message: str,
) -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(
        policy.sha256, key["actor_id"], issued_at="2026-01-01T00:00:00Z"
    )

    with pytest.raises(IntegrityError, match=message):
        _verify_policy_statement(
            policy,
            _signed_statement(
                signed_predicate_type,
                predicate,
                [private_keys["DISCOVERY_AUTHORITY"]],
                statement_extra=statement_extra,
            ),
            _AUTHORITY_TYPE,
        )


def test_statement_transport_unknown_field_is_allowed_but_predicate_extra_is_strict() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(
        policy.sha256, key["actor_id"], issued_at="2026-01-01T00:00:00Z"
    )

    transport_compatible = _signed_statement(
        _AUTHORITY_TYPE,
        predicate,
        [private_keys["DISCOVERY_AUTHORITY"]],
        statement_extra={"futureStatementField": {"ignored": True}},
    )
    assert _verify_policy_statement(
        policy, transport_compatible, _AUTHORITY_TYPE
    ).production_qualified

    predicate["futurePredicateField"] = "must reject"
    with pytest.raises(SchemaValidationError):
        _verify_policy_statement(
            policy,
            _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["DISCOVERY_AUTHORITY"]]),
            _AUTHORITY_TYPE,
        )


def test_shadow_policy_can_verify_evidence_but_never_production_qualifies() -> None:
    document, private_keys = _policy_document(mode="SHADOW")
    policy = _load_policy_document(document)
    key = _key_entry(document, "DISCOVERY_AUTHORITY")
    predicate = _authority_predicate(
        policy.sha256, key["actor_id"], issued_at="2026-01-01T00:00:00Z"
    )

    verified = _verify_policy_statement(
        policy,
        _signed_statement(_AUTHORITY_TYPE, predicate, [private_keys["DISCOVERY_AUTHORITY"]]),
        _AUTHORITY_TYPE,
    )

    assert verified.trust_mode == "SHADOW"
    assert verified.production_qualified is False


@pytest.mark.parametrize(
    ("sealed_at", "development_at", "evaluator_access"),
    [
        ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", False),
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", False),
        ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", True),
    ],
)
def test_custody_chronology_is_strict_and_evaluator_must_not_have_hidden_access(
    sealed_at: str,
    development_at: str,
    evaluator_access: bool,
) -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "CUSTODIAN")
    predicate = _custody_predicate(policy.sha256, key["actor_id"])
    predicate.update(
        sealed_at=sealed_at,
        explorer_development_started_at=development_at,
        evaluator_access=evaluator_access,
    )

    verified = _verify_policy_statement(
        policy,
        _signed_statement(_CUSTODY_TYPE, predicate, [private_keys["CUSTODIAN"]]),
        _CUSTODY_TYPE,
    )

    assert verified.production_qualified is False


def test_trial_matrix_requires_the_exact_seven_by_five_cartesian_product() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "TRIAL_EVALUATOR")
    predicate = _trial_predicate(policy.sha256, key["actor_id"])
    for index, binding in enumerate(predicate["run_bindings"]):
        binding["case_id"] = f"case-{index + 1}"

    with pytest.raises(IntegrityError, match="matrix"):
        _verify_policy_statement(
            policy,
            _signed_statement(_TRIAL_TYPE, predicate, [private_keys["TRIAL_EVALUATOR"]]),
            _TRIAL_TYPE,
        )


@pytest.mark.parametrize(
    "observed_patch",
    [
        {"false_verified_claims": 1},
        {
            "trusted_verified_positives": 3,
            "claimed_verified_total": 0,
            "clean_replay_verified": 0,
        },
        {"claimed_verified_total": 2, "clean_replay_verified": 2},
        {"clean_replay_verified": 4},
    ],
)
def test_trial_observed_counts_cannot_launder_thresholds(observed_patch: dict) -> None:
    document, private_keys = _policy_document()
    policy = _load_policy_document(document)
    key = _key_entry(document, "TRIAL_EVALUATOR")
    predicate = _trial_predicate(policy.sha256, key["actor_id"])
    predicate["observed"].update(observed_patch)

    with pytest.raises(IntegrityError, match="observation|count|claim"):
        _verify_policy_statement(
            policy,
            _signed_statement(_TRIAL_TYPE, predicate, [private_keys["TRIAL_EVALUATOR"]]),
            _TRIAL_TYPE,
        )
