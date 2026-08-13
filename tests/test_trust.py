from __future__ import annotations

import base64
from copy import deepcopy
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unasked.errors import IntegrityError, UsageError
from unasked.trust import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    PREDICATE_ROLES,
    TrustedEd25519Key,
    TrustPolicy,
    VerifiedStatement,
    _predicate_qualifies,
    dsse_b64decode,
    dsse_pae,
    load_trust_policy,
    parse_strict_json,
    strict_b64decode,
    verify_dsse_json_envelope,
    verify_dsse_statement,
    verify_ed25519,
)
from unasked.util import canonical_json, sha256_bytes

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_HASH = "a" * 64
_ISSUED = "2026-08-13T07:00:00Z"
_POLICY_FROM = "2026-08-01T00:00:00Z"
_POLICY_UNTIL = "2026-09-01T00:00:00Z"


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _envelope(
    payload: bytes,
    private_key: Ed25519PrivateKey,
    *,
    keyid: str = "trusted-key",
    payload_type: str = _PAYLOAD_TYPE,
) -> bytes:
    signature = private_key.sign(dsse_pae(payload_type, payload))
    return canonical_json(
        {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"keyid": keyid, "sig": base64.b64encode(signature).decode("ascii")}],
        }
    )


def _policy_document(*, mode: str = "PRODUCTION") -> tuple[dict, dict[str, Ed25519PrivateKey]]:
    keys: list[dict] = []
    private_keys: dict[str, Ed25519PrivateKey] = {}
    thresholds: list[dict] = []
    predicate_roles: list[dict] = []
    for index, (predicate_type, (role, _)) in enumerate(PREDICATE_ROLES.items(), start=1):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes([index + 20]) * 32)
        private_keys[role] = private_key
        keys.append(
            {
                "key_id": f"key-{index}",
                "actor_id": f"actor-{index}",
                "role": role,
                "status": "ACTIVE",
                "public_key_base64": base64.b64encode(_raw_public_key(private_key)).decode(),
                "valid_from": _POLICY_FROM,
                "valid_until": _POLICY_UNTIL,
            }
        )
        thresholds.append({"role": role, "minimum_signatures": 1})
        predicate_roles.append({"predicate_type": predicate_type, "role": role})
    return (
        {
            "schema_version": "0.4.0",
            "policy_id": "policy-1",
            "mode": mode,
            "issued_at": _POLICY_FROM,
            "valid_from": _POLICY_FROM,
            "valid_until": _POLICY_UNTIL,
            "algorithm": "Ed25519",
            "dsse_payload_type": DSSE_PAYLOAD_TYPE,
            "statement_type": IN_TOTO_STATEMENT_TYPE,
            "keys": keys,
            "thresholds": thresholds,
            "predicate_roles": predicate_roles,
            "separation": {
                "unique_public_keys": mode == "PRODUCTION",
                "one_role_per_key": mode == "PRODUCTION",
                "distinct_actor_ids_across_roles": mode == "PRODUCTION",
            },
        },
        private_keys,
    )


def _load_policy(document: dict) -> TrustPolicy:
    policy_bytes = canonical_json(document)
    return load_trust_policy(
        policy_bytes,
        expected_sha256=sha256_bytes(policy_bytes),
        now=datetime(2026, 8, 13, 8, tzinfo=UTC),
    )


def _custody_predicate(policy: TrustPolicy) -> dict:
    return {
        "schema_version": "0.4.0",
        "predicate_id": "predicate-1",
        "issued_at": _ISSUED,
        "issuer_actor_id": "actor-2",
        "trust_policy_sha256": policy.sha256,
        "suite_id": "suite-1",
        "manifest_sha256": _HASH,
        "case_commitment_sha256": _HASH,
        "sealed_at": "2026-08-10T00:00:00Z",
        "explorer_development_started_at": "2026-08-11T00:00:00Z",
        "independent_custody": True,
        "sealed_before_explorer": True,
        "hidden_case_count": 7,
        "positive_case_count": 5,
        "control_case_count": 2,
        "explorer_ground_truth_access": False,
        "evaluator_access": False,
        "directional_steering": False,
    }


def _statement(predicate_type: str, predicate: dict) -> bytes:
    return canonical_json(
        {
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [{"name": "opaque-external-evidence"}],
            "predicateType": predicate_type,
            "predicate": predicate,
            "futureStatementField": "ignored",
        }
    )


def test_strict_json_accepts_utf8_and_rejects_duplicates_nonfinite_and_invalid_bytes() -> None:
    assert parse_strict_json('{"message":"證據","value":1}'.encode()) == {
        "message": "證據",
        "value": 1,
    }

    for invalid in (
        b'{"outer":{"same":1,"same":2}}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"message":"\xff"}',
        b'{"incomplete":',
    ):
        with pytest.raises(UsageError, match="strict UTF-8 JSON"):
            parse_strict_json(invalid)


def test_dsse_pae_v1_0_2_uses_utf8_byte_lengths_and_exact_payload_bytes() -> None:
    assert dsse_pae("text/plain", b"abc") == b"DSSEv1 10 text/plain 3 abc"
    assert dsse_pae("類型", b"\x00\xff") == (b"DSSEv1 6 " + "類型".encode() + b" 2 \x00\xff")


@pytest.mark.parametrize("urlsafe", [False, True])
def test_base64_requires_selected_alphabet_padding_and_canonical_reencoding(
    urlsafe: bool,
) -> None:
    raw = b"\xfb\xef"
    encoded = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
    assert strict_b64decode(encoded, urlsafe=urlsafe) == raw

    wrong_alphabet = (base64.b64encode(raw) if urlsafe else base64.urlsafe_b64encode(raw)).decode(
        "ascii"
    )
    for invalid in (encoded.rstrip("="), encoded + "\n", f" {encoded}", wrong_alphabet):
        with pytest.raises(UsageError, match="Base64"):
            strict_b64decode(invalid, urlsafe=urlsafe)


def test_dsse_base64_accepts_both_standard_and_urlsafe_alphabets() -> None:
    raw = b"\xfb\xef"
    assert dsse_b64decode(base64.b64encode(raw).decode("ascii")) == raw
    assert dsse_b64decode(base64.urlsafe_b64encode(raw).decode("ascii")) == raw


def test_ed25519_verifies_exact_message_and_rejects_tampering() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    public_key = _raw_public_key(private_key)
    signature = private_key.sign(b"exact-message")

    assert verify_ed25519(
        public_key=public_key,
        signature=signature,
        message=b"exact-message",
    )
    assert not verify_ed25519(
        public_key=public_key,
        signature=signature,
        message=b"different-message",
    )


def test_dsse_verifier_returns_only_payload_parsed_from_verified_exact_bytes() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
    payload = b'{"z":1, "message":"verified bytes"}'
    envelope = _envelope(payload, private_key)

    verified = verify_dsse_json_envelope(
        envelope,
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[TrustedEd25519Key(_raw_public_key(private_key), "trusted-key")],
    )

    assert verified == {"message": "verified bytes", "z": 1}
    assert set(verified) == {"message", "z"}


def test_dsse_keyid_is_only_a_hint_and_never_adds_authority() -> None:
    trusted_private = Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)
    attacker_private = Ed25519PrivateKey.from_private_bytes(b"\x04" * 32)
    trusted = TrustedEd25519Key(_raw_public_key(trusted_private), "trusted-key")
    payload = canonical_json({"claim": "structural evidence"})

    misleading_but_valid = _envelope(payload, trusted_private, keyid="attacker-label")
    assert verify_dsse_json_envelope(
        misleading_but_valid,
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[trusted],
    ) == {"claim": "structural evidence"}

    forged_hint = _envelope(payload, attacker_private, keyid="trusted-key")
    with pytest.raises(IntegrityError, match="caller-trusted"):
        verify_dsse_json_envelope(
            forged_hint,
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[trusted],
        )


def test_dsse_optional_keyid_and_unknown_fields_follow_envelope_v1_0_2() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    trusted = TrustedEd25519Key(_raw_public_key(private_key), "trusted-key")
    envelope = parse_strict_json(_envelope(b'{"verified":true}', private_key))
    envelope["futureEnvelopeField"] = {"ignored": True}
    envelope["signatures"][0].pop("keyid")
    envelope["signatures"][0]["futureSignatureField"] = "ignored"

    assert verify_dsse_json_envelope(
        canonical_json(envelope),
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[trusted],
    ) == {"verified": True}


def test_dsse_urlsafe_envelope_payload_and_signature_verify() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x08" * 32)
    payload = b'{"bytes":"\\uffff"}'
    signature = private_key.sign(dsse_pae(_PAYLOAD_TYPE, payload))
    envelope = canonical_json(
        {
            "payloadType": _PAYLOAD_TYPE,
            "payload": base64.urlsafe_b64encode(payload).decode("ascii"),
            "signatures": [{"sig": base64.urlsafe_b64encode(signature).decode("ascii")}],
        }
    )

    assert verify_dsse_json_envelope(
        envelope,
        expected_payload_type=_PAYLOAD_TYPE,
        trusted_keys=[TrustedEd25519Key(_raw_public_key(private_key))],
    ) == {"bytes": "\uffff"}


def test_dsse_threshold_counts_unique_trusted_keys_not_repeated_signatures() -> None:
    first = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
    second = Ed25519PrivateKey.from_private_bytes(b"\x0a" * 32)
    payload = b"{}"
    first_signature = base64.b64encode(first.sign(dsse_pae(_PAYLOAD_TYPE, payload))).decode()
    envelope = {
        "payloadType": _PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": "first", "sig": first_signature},
            {"keyid": "first", "sig": first_signature},
        ],
    }
    trusted = [
        TrustedEd25519Key(_raw_public_key(first), "first"),
        TrustedEd25519Key(_raw_public_key(second), "second"),
    ]

    with pytest.raises(IntegrityError, match="threshold"):
        verify_dsse_json_envelope(
            canonical_json(envelope),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
            threshold=2,
        )

    second_signature = base64.b64encode(second.sign(dsse_pae(_PAYLOAD_TYPE, payload))).decode()
    envelope["signatures"].append({"keyid": "second", "sig": second_signature})
    assert (
        verify_dsse_json_envelope(
            canonical_json(envelope),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=trusted,
            threshold=2,
        )
        == {}
    )


def test_dsse_rejects_payload_type_confusion_and_post_signature_json_laundering() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    trusted = TrustedEd25519Key(_raw_public_key(private_key), "trusted-key")
    payload = b'{"same":1,"same":2}'
    envelope = _envelope(payload, private_key)

    with pytest.raises(UsageError, match="strict UTF-8 JSON"):
        verify_dsse_json_envelope(
            envelope,
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[trusted],
        )
    with pytest.raises(IntegrityError, match="payloadType"):
        verify_dsse_json_envelope(
            envelope,
            expected_payload_type="application/example+json",
            trusted_keys=[trusted],
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"signatures": []},
        {"signatures": [{"keyid": "trusted-key", "sig": "not base64"}]},
    ],
)
def test_dsse_envelope_shape_and_encoding_fail_closed(mutation: dict) -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
    trusted = TrustedEd25519Key(_raw_public_key(private_key), "trusted-key")
    envelope = parse_strict_json(_envelope(b"{}", private_key))
    envelope.update(mutation)

    with pytest.raises((UsageError, IntegrityError)):
        verify_dsse_json_envelope(
            canonical_json(envelope),
            expected_payload_type=_PAYLOAD_TYPE,
            trusted_keys=[trusted],
        )


def test_trust_policy_is_exact_byte_pinned_before_strict_json_parse() -> None:
    invalid_bytes = b'{"duplicate":1,"duplicate":2}'
    with pytest.raises(UsageError, match="64 lowercase hex"):
        load_trust_policy(invalid_bytes, expected_sha256="not-a-pin")
    with pytest.raises(IntegrityError, match="exact-byte"):
        load_trust_policy(invalid_bytes, expected_sha256="0" * 64)
    with pytest.raises(UsageError, match="strict UTF-8 JSON"):
        load_trust_policy(invalid_bytes, expected_sha256=sha256_bytes(invalid_bytes))


def test_trust_policy_loads_external_keys_roles_thresholds_and_exact_bytes() -> None:
    document, _ = _policy_document()
    policy_bytes = canonical_json(document)
    policy = _load_policy(document)

    assert policy.policy_bytes is policy_bytes or policy.policy_bytes == policy_bytes
    assert policy.sha256 == sha256_bytes(policy_bytes)
    assert policy.mode == "PRODUCTION"
    assert policy.threshold_for("https://schemas.unasked.dev/attestations/custody/v0.4") == 1
    assert (
        policy.keys_for("https://schemas.unasked.dev/attestations/custody/v0.4")[0].role
        == "CUSTODIAN"
    )


@pytest.mark.parametrize("duplicate", ["key_id", "public_key_base64"])
def test_trust_policy_rejects_duplicate_key_identity_or_raw_key(duplicate: str) -> None:
    document, _ = _policy_document()
    document["keys"][1][duplicate] = document["keys"][0][duplicate]
    with pytest.raises(IntegrityError, match="duplicate"):
        _load_policy(document)


def test_production_policy_rejects_actor_overlap_across_roles_and_same_actor_threshold() -> None:
    document, _ = _policy_document()
    document["keys"][1]["actor_id"] = document["keys"][0]["actor_id"]
    with pytest.raises(IntegrityError, match="span trust roles"):
        _load_policy(document)

    document, _ = _policy_document()
    custodian = deepcopy(document["keys"][1])
    custodian["key_id"] = "custodian-second-key"
    second_private = Ed25519PrivateKey.from_private_bytes(b"\x40" * 32)
    custodian["public_key_base64"] = base64.b64encode(_raw_public_key(second_private)).decode()
    document["keys"].append(custodian)
    document["thresholds"][1]["minimum_signatures"] = 2
    with pytest.raises(IntegrityError, match="distinct configured signers"):
        _load_policy(document)


def test_policy_rejects_not_yet_valid_expired_and_out_of_policy_key_ranges() -> None:
    document, _ = _policy_document()
    with pytest.raises(IntegrityError, match="verification time"):
        load_trust_policy(
            canonical_json(document),
            expected_sha256=sha256_bytes(canonical_json(document)),
            now="2026-07-31T23:59:59Z",
        )
    document["keys"][0]["valid_until"] = "2026-09-02T00:00:00Z"
    with pytest.raises(IntegrityError, match="within policy validity"):
        _load_policy(document)


def test_verified_statement_returns_exact_signed_bytes_and_authenticated_identities() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy(document)
    predicate_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    payload = _statement(predicate_type, _custody_predicate(policy))
    envelope = _envelope(payload, private_keys["CUSTODIAN"], keyid="untrusted-hint")

    verified = verify_dsse_statement(
        envelope,
        expected_predicate_type=predicate_type,
        trusted_keys=policy.keys_for(predicate_type),
        threshold=policy.threshold_for(predicate_type),
        predicate_schema="custody-attestation-predicate",
    )

    assert isinstance(verified, VerifiedStatement)
    assert verified.payload_bytes == payload
    assert verified.payload_sha256 == sha256_bytes(payload)
    assert verified.signer_actor_ids == ("actor-2",)
    assert verified.signer_roles == ("CUSTODIAN",)
    assert verified.trust_mode == "PRODUCTION"
    assert verified.production_qualified is True


def test_statement_rejects_wrong_role_revoked_time_invalid_and_predicate_injection() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy(document)
    predicate_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    predicate = _custody_predicate(policy)

    with pytest.raises(IntegrityError, match="required predicate role"):
        verify_dsse_statement(
            _envelope(_statement(predicate_type, predicate), private_keys["CUSTODIAN"]),
            expected_predicate_type=predicate_type,
            trusted_keys=policy.keys_for("https://schemas.unasked.dev/attestations/isolation/v0.4"),
            threshold=1,
            predicate_schema="custody-attestation-predicate",
        )

    revoked = tuple(
        TrustedEd25519Key(
            **{
                field: getattr(key, field)
                for field in (
                    "public_key",
                    "keyid",
                    "actor_id",
                    "role",
                    "valid_from",
                    "valid_until",
                    "trust_mode",
                    "policy_sha256",
                    "policy_valid_from",
                    "policy_valid_until",
                )
            },
            status="REVOKED",
        )
        for key in policy.keys_for(predicate_type)
    )
    with pytest.raises(IntegrityError, match="active, time-valid"):
        verify_dsse_statement(
            _envelope(_statement(predicate_type, predicate), private_keys["CUSTODIAN"]),
            expected_predicate_type=predicate_type,
            trusted_keys=revoked,
            threshold=1,
            predicate_schema="custody-attestation-predicate",
        )

    injected = {**predicate, "production_override": True}
    with pytest.raises(ValueError, match="schema validation"):
        verify_dsse_statement(
            _envelope(_statement(predicate_type, injected), private_keys["CUSTODIAN"]),
            expected_predicate_type=predicate_type,
            trusted_keys=policy.keys_for(predicate_type),
            threshold=1,
            predicate_schema="custody-attestation-predicate",
        )


def test_shadow_statement_can_verify_but_never_production_qualifies() -> None:
    document, private_keys = _policy_document(mode="SHADOW")
    policy = _load_policy(document)
    predicate_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    result = verify_dsse_statement(
        _envelope(
            _statement(predicate_type, _custody_predicate(policy)),
            private_keys["CUSTODIAN"],
        ),
        expected_predicate_type=predicate_type,
        trusted_keys=policy.keys_for(predicate_type),
        threshold=1,
        predicate_schema="custody-attestation-predicate",
    )
    assert result.trust_mode == "SHADOW"
    assert result.production_qualified is False


def test_predicate_issued_at_must_be_inside_pinned_policy_and_key_validity() -> None:
    document, private_keys = _policy_document()
    policy = _load_policy(document)
    predicate_type = "https://schemas.unasked.dev/attestations/custody/v0.4"
    predicate = _custody_predicate(policy)
    predicate["issued_at"] = "2026-09-01T00:00:01Z"

    with pytest.raises(IntegrityError, match="active, time-valid"):
        verify_dsse_statement(
            _envelope(_statement(predicate_type, predicate), private_keys["CUSTODIAN"]),
            expected_predicate_type=predicate_type,
            trusted_keys=policy.keys_for(predicate_type),
            threshold=1,
            predicate_schema="custody-attestation-predicate",
        )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"evaluator_access": True}, False),
        ({"sealed_at": "2026-08-11T00:00:00Z"}, False),
        ({"hidden_case_count": 6}, False),
    ],
)
def test_custody_production_qualifier_requires_strict_blind_sealing(
    mutation: dict, expected: bool
) -> None:
    document, _ = _policy_document()
    predicate = {**_custody_predicate(_load_policy(document)), **mutation}
    assert (
        _predicate_qualifies("https://schemas.unasked.dev/attestations/custody/v0.4", predicate)
        is expected
    )


def test_trial_matrix_requires_exact_five_by_seven_cartesian_and_consistent_counts() -> None:
    variants = tuple(
        {
            "deterministic-detectors-only",
            "read-only-llm-reviewer",
            "llm-tools-no-experiment-gate",
            "experiment-loop-without-falsifier",
            "full-evidence-gated-system",
        }
    )
    bindings = [
        {"variant": variant, "case_id": f"case-{case}", "run_id": f"run-{variant}-{case}"}
        for variant in variants
        for case in range(7)
    ]
    predicate = {
        "issued_at": _ISSUED,
        "run_bindings": bindings,
        "observed": {
            "trusted_verified_positives": 0,
            "false_verified_controls": 0,
            "false_verified_claims": 0,
            "claimed_verified_total": 0,
            "clean_replay_verified": 0,
            "context_provenance_complete": False,
            "target_snapshot_immutable": False,
            "hidden_inputs_immutable": False,
            "scoring_policy_immutable": False,
        },
        "gates": {
            "matrix_complete": True,
            "independent_custody": False,
            "sealed_before_explorer": False,
            "actor_identities_authenticated": False,
            "isolation_attestations_authenticated": False,
            "ledger_checkpoints_authenticated": False,
            "certificate_graphs_valid": False,
            "positive_threshold_met": False,
            "control_threshold_met": True,
            "clean_replay_complete": True,
            "context_provenance_complete": False,
            "inputs_immutable": False,
        },
        "status": "NOT_MET",
    }
    assert not _predicate_qualifies(
        "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4", predicate
    )

    forged = deepcopy(predicate)
    for index, binding in enumerate(forged["run_bindings"]):
        binding["variant"] = variants[0]
        binding["case_id"] = f"invented-case-{index}"
    with pytest.raises(IntegrityError, match="35-run matrix"):
        _predicate_qualifies(
            "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4", forged
        )

    inconsistent = deepcopy(predicate)
    inconsistent["observed"]["trusted_verified_positives"] = 3
    with pytest.raises(IntegrityError, match="internally inconsistent"):
        _predicate_qualifies(
            "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4", inconsistent
        )
