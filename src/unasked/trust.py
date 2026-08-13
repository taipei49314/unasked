"""Fail-closed primitives for externally rooted signed evidence.

This module verifies bytes; it does not create keys, select a production trust root,
or grant authority to an envelope-provided key identifier.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from unasked.errors import IntegrityError, UsageError
from unasked.schemas import validate_or_raise
from unasked.util import sha256_bytes

DSSE_VERSION = "1.0.2"
DSSE_PAE_PREFIX = b"DSSEv1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

PREDICATE_ROLES = {
    "https://schemas.unasked.dev/attestations/authority-authorization/v0.4": (
        "DISCOVERY_AUTHORITY",
        "authority-authorization-predicate",
    ),
    "https://schemas.unasked.dev/attestations/custody/v0.4": (
        "CUSTODIAN",
        "custody-attestation-predicate",
    ),
    "https://schemas.unasked.dev/attestations/isolation/v0.4": (
        "ISOLATION_ATTESTER",
        "isolation-attestation-predicate",
    ),
    "https://schemas.unasked.dev/attestations/ledger-checkpoint/v0.4": (
        "LEDGER_WITNESS",
        "ledger-checkpoint-predicate",
    ),
    "https://schemas.unasked.dev/attestations/trial-evaluation/v0.4": (
        "TRIAL_EVALUATOR",
        "trial-evaluation-predicate",
    ),
    "https://schemas.unasked.dev/attestations/m0-certification/v0.4": (
        "M0_CERTIFIER",
        "m0-certification-predicate",
    ),
}
TRIAL_VARIANTS = frozenset(
    {
        "deterministic-detectors-only",
        "read-only-llm-reviewer",
        "llm-tools-no-experiment-gate",
        "experiment-loop-without-falsifier",
        "full-evidence-gated-system",
    }
)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is forbidden: {value}.")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key is forbidden: {key!r}.")
        result[key] = value
    return result


def parse_strict_json(data: bytes | bytearray | memoryview) -> Any:
    """Parse one UTF-8 JSON value while rejecting duplicate keys and non-finite numbers."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise UsageError("Strict JSON input must be bytes-like.")
    raw = bytes(data)
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise UsageError(
            "Signed JSON payload is not strict UTF-8 JSON.",
            details={"reason": str(exc)},
        ) from exc


def strict_b64decode(value: str, *, urlsafe: bool = False) -> bytes:
    """Decode canonical padded base64 in the selected alphabet.

    Decoding is strict and the original text must equal a canonical re-encoding. This
    rejects whitespace, discarded characters, mixed alphabets, and alternate padding.
    """

    if not isinstance(value, str):
        raise UsageError("Base64 input must be a string.")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(
            encoded,
            altchars=b"-_" if urlsafe else None,
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise UsageError(
            "Base64 input is invalid.",
            details={"alphabet": "URL_SAFE" if urlsafe else "STANDARD"},
        ) from exc
    canonical = (
        base64.urlsafe_b64encode(decoded) if urlsafe else base64.b64encode(decoded)
    ).decode("ascii")
    if value != canonical:
        raise UsageError(
            "Base64 input is not canonically encoded.",
            details={"alphabet": "URL_SAFE" if urlsafe else "STANDARD"},
        )
    return decoded


def dsse_b64decode(value: str) -> bytes:
    """Decode canonical padded standard or URL-safe base64 as required by DSSE."""

    errors: list[UsageError] = []
    for urlsafe in (False, True):
        try:
            return strict_b64decode(value, urlsafe=urlsafe)
        except UsageError as exc:
            errors.append(exc)
    raise UsageError("DSSE base64 input is invalid in both permitted alphabets.") from errors[-1]


def dsse_pae(payload_type: str, payload: bytes | bytearray | memoryview) -> bytes:
    """Return DSSE v1.0.2 Pre-Authentication Encoding for exact payload bytes."""

    if not isinstance(payload_type, str):
        raise UsageError("DSSE payloadType must be a string.")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise UsageError("DSSE payload must be bytes-like.")
    try:
        type_bytes = payload_type.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise UsageError("DSSE payloadType must be valid Unicode.") from exc
    payload_bytes = bytes(payload)
    return b" ".join(
        (
            DSSE_PAE_PREFIX,
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload_bytes)).encode("ascii"),
            payload_bytes,
        )
    )


@dataclass(frozen=True, slots=True)
class TrustedEd25519Key:
    """Caller-supplied trusted Ed25519 key; ``keyid`` is only an optimization hint."""

    public_key: bytes
    keyid: str | None = None
    actor_id: str | None = None
    role: str | None = None
    status: str = "ACTIVE"
    valid_from: str | None = None
    valid_until: str | None = None
    trust_mode: str | None = None
    policy_sha256: str | None = None
    policy_valid_from: str | None = None
    policy_valid_until: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise UsageError("Trusted Ed25519 public keys must be exactly 32 raw bytes.")
        if self.keyid is not None and (not isinstance(self.keyid, str) or not self.keyid):
            raise UsageError("Trusted Ed25519 keyid hints must be non-empty strings.")

    @property
    def fingerprint(self) -> str:
        """A stable identity derived from the raw public key, never from ``keyid``."""

        return sha256_bytes(self.public_key)


@dataclass(frozen=True, slots=True)
class VerifiedStatement:
    """An in-toto Statement parsed only from the exact DSSE-verified payload bytes."""

    payload_bytes: bytes
    payload_sha256: str
    statement: dict[str, Any]
    predicate: dict[str, Any]
    signer_fingerprints: tuple[str, ...]
    signer_key_ids: tuple[str, ...]
    signer_actor_ids: tuple[str, ...]
    signer_roles: tuple[str, ...]
    trust_mode: str
    production_qualified: bool


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """An exact-byte-pinned external trust policy and its validated key material."""

    policy_bytes: bytes
    sha256: str
    document: dict[str, Any]
    keys: tuple[TrustedEd25519Key, ...]
    thresholds: dict[str, int]
    predicate_roles: dict[str, str]

    @property
    def policy_id(self) -> str:
        return str(self.document["policy_id"])

    @property
    def mode(self) -> str:
        return str(self.document["mode"])

    def keys_for(self, predicate_type: str) -> tuple[TrustedEd25519Key, ...]:
        """Return policy keys for a declared predicate role, without time laundering."""

        try:
            role = self.predicate_roles[predicate_type]
        except KeyError as exc:
            raise UsageError("Predicate type is not authorized by this trust policy.") from exc
        return tuple(key for key in self.keys if key.role == role)

    def threshold_for(self, predicate_type: str) -> int:
        role = self.predicate_roles.get(predicate_type)
        if role is None:
            raise UsageError("Predicate type is not authorized by this trust policy.")
        return self.thresholds[role]


def verify_ed25519(*, public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return whether a raw Ed25519 signature verifies over the exact message bytes."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise UsageError("Ed25519 public key must be exactly 32 raw bytes.")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise UsageError("Ed25519 signature must be exactly 64 raw bytes.")
    if not isinstance(message, bytes):
        raise UsageError("Ed25519 message must be bytes.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def _candidate_keys(
    trusted_keys: Sequence[TrustedEd25519Key],
    untrusted_keyid: str,
) -> tuple[TrustedEd25519Key, ...]:
    hinted = [key for key in trusted_keys if key.keyid == untrusted_keyid]
    remaining = [key for key in trusted_keys if key.keyid != untrusted_keyid]
    return tuple((*hinted, *remaining))


def _decode_and_verify_dsse(
    envelope_bytes: bytes | bytearray | memoryview,
    *,
    expected_payload_type: str,
    trusted_keys: Sequence[TrustedEd25519Key],
    threshold: int,
) -> tuple[bytes, Any, tuple[TrustedEd25519Key, ...]]:
    if not isinstance(expected_payload_type, str) or not expected_payload_type:
        raise UsageError("Expected DSSE payloadType must be a non-empty string.")
    if not isinstance(trusted_keys, Sequence) or isinstance(
        trusted_keys, (str, bytes, bytearray, memoryview)
    ):
        raise UsageError("Trusted Ed25519 keys must be a sequence.")
    normalized_keys = tuple(trusted_keys)
    if not normalized_keys or not all(
        isinstance(key, TrustedEd25519Key) for key in normalized_keys
    ):
        raise UsageError("At least one caller-trusted Ed25519 key is required.")
    unique_trusted_keys = {key.public_key for key in normalized_keys}
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
        or threshold > len(unique_trusted_keys)
    ):
        raise UsageError(
            "DSSE signature threshold must fit the unique caller-trusted key set.",
            details={"threshold": threshold, "unique_trusted_keys": len(unique_trusted_keys)},
        )

    envelope = parse_strict_json(envelope_bytes)
    if not isinstance(envelope, dict) or not {
        "payloadType",
        "payload",
        "signatures",
    }.issubset(envelope):
        raise UsageError("DSSE envelope is missing required fields.")
    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str) or payload_type != expected_payload_type:
        raise IntegrityError(
            "DSSE payloadType does not match the caller's expected type.",
            details={"expected": expected_payload_type, "actual": payload_type},
        )
    payload = dsse_b64decode(envelope["payload"])
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not signatures:
        raise UsageError("DSSE envelope requires at least one signature.")

    message = dsse_pae(payload_type, payload)
    accepted: dict[bytes, TrustedEd25519Key] = {}
    for signature_entry in signatures:
        if not isinstance(signature_entry, dict) or "sig" not in signature_entry:
            raise UsageError("DSSE signature is missing its required sig field.")
        untrusted_keyid = signature_entry.get("keyid", "")
        if not isinstance(untrusted_keyid, str):
            raise UsageError("DSSE signature keyid must be a string.")
        signature = dsse_b64decode(signature_entry["sig"])
        for trusted_key in _candidate_keys(normalized_keys, untrusted_keyid):
            if trusted_key.public_key in accepted:
                continue
            if verify_ed25519(
                public_key=trusted_key.public_key,
                signature=signature,
                message=message,
            ):
                accepted[trusted_key.public_key] = trusted_key
                break
    if len(accepted) < threshold:
        raise IntegrityError(
            "DSSE signature threshold is not met by unique caller-trusted keys.",
            details={"required": threshold, "verified_unique_keys": len(accepted)},
        )
    parsed = parse_strict_json(payload)
    signers = tuple(sorted(accepted.values(), key=lambda item: item.fingerprint))
    return payload, parsed, signers


def verify_dsse_json_envelope(
    envelope_bytes: bytes | bytearray | memoryview,
    *,
    expected_payload_type: str,
    trusted_keys: Sequence[TrustedEd25519Key],
    threshold: int = 1,
) -> Any:
    """Verify a strict DSSE JSON envelope and return its verified JSON payload.

    The envelope's ``keyid`` values only order caller-trusted key candidates. They never
    add a key to the trust set and a valid signature is always required. Payload bytes are
    decoded once, verified as-is, and only then parsed from that same byte string.
    """

    _, parsed, _ = _decode_and_verify_dsse(
        envelope_bytes,
        expected_payload_type=expected_payload_type,
        trusted_keys=trusted_keys,
        threshold=threshold,
    )
    return parsed


def _timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise UsageError(f"{field} must be an RFC 3339 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageError(f"{field} must be an RFC 3339 timestamp.") from exc
    if parsed.tzinfo is None:
        raise UsageError(f"{field} must include a timezone.")
    return parsed.astimezone(UTC)


def _now(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, str):
        return _timestamp(value, "now")
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise UsageError("now must be a timezone-aware datetime or RFC 3339 string.")
    return value.astimezone(UTC)


def load_trust_policy(
    policy_bytes: bytes,
    *,
    expected_sha256: str,
    now: datetime | str | None = None,
) -> TrustPolicy:
    """Pin exact policy bytes before parsing and return a semantically validated policy."""

    if not isinstance(policy_bytes, bytes):
        raise UsageError("Trust policy input must be exact bytes.")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise UsageError("Expected trust policy SHA-256 must be 64 lowercase hex characters.")
    actual_sha256 = sha256_bytes(policy_bytes)
    if not hmac.compare_digest(expected_sha256, actual_sha256):
        raise IntegrityError(
            "Trust policy exact-byte SHA-256 pin does not match.",
            details={"expected": expected_sha256, "actual": actual_sha256},
        )
    document = parse_strict_json(policy_bytes)
    if not isinstance(document, dict):
        raise UsageError("Trust policy must be a JSON object.")
    validate_or_raise("trust-policy", document)

    current = _now(now)
    issued_at = _timestamp(document["issued_at"], "issued_at")
    valid_from = _timestamp(document["valid_from"], "valid_from")
    valid_until = _timestamp(document["valid_until"], "valid_until")
    if valid_from > valid_until or issued_at > current or not valid_from <= current <= valid_until:
        raise IntegrityError("Trust policy is not valid at the verification time.")

    mode = document["mode"]
    key_ids: set[str] = set()
    public_keys: set[bytes] = set()
    actor_roles: dict[str, str] = {}
    keys: list[TrustedEd25519Key] = []
    for item in document["keys"]:
        public_key = strict_b64decode(item["public_key_base64"])
        if len(public_key) != 32:
            raise UsageError("Trust policy Ed25519 public keys must be exactly 32 bytes.")
        key_from = _timestamp(item["valid_from"], "key.valid_from")
        key_until = _timestamp(item["valid_until"], "key.valid_until")
        if key_from > key_until or key_from < valid_from or key_until > valid_until:
            raise IntegrityError(
                "Trust policy key validity must be ordered within policy validity."
            )
        if item["key_id"] in key_ids:
            raise IntegrityError("Trust policy contains a duplicate key_id.")
        if public_key in public_keys:
            raise IntegrityError("Trust policy contains a duplicate raw public key.")
        key_ids.add(item["key_id"])
        public_keys.add(public_key)
        previous_role = actor_roles.setdefault(item["actor_id"], item["role"])
        if mode == "PRODUCTION" and previous_role != item["role"]:
            raise IntegrityError("Production trust policy actors may not span trust roles.")
        keys.append(
            TrustedEd25519Key(
                public_key=public_key,
                keyid=item["key_id"],
                actor_id=item["actor_id"],
                role=item["role"],
                status=item["status"],
                valid_from=item["valid_from"],
                valid_until=item["valid_until"],
                trust_mode=mode,
                policy_sha256=actual_sha256,
                policy_valid_from=document["valid_from"],
                policy_valid_until=document["valid_until"],
            )
        )

    threshold_items = document["thresholds"]
    thresholds = {item["role"]: item["minimum_signatures"] for item in threshold_items}
    if len(thresholds) != len(threshold_items) or set(thresholds) != {
        role for role, _ in PREDICATE_ROLES.values()
    }:
        raise IntegrityError("Trust policy must declare exactly one threshold for every role.")
    mapping_items = document["predicate_roles"]
    predicate_roles = {item["predicate_type"]: item["role"] for item in mapping_items}
    if len(predicate_roles) != len(mapping_items) or set(predicate_roles) != set(PREDICATE_ROLES):
        raise IntegrityError("Trust policy must bind every predicate type exactly once.")
    for predicate_type, (expected_role, _) in PREDICATE_ROLES.items():
        if predicate_roles[predicate_type] != expected_role:
            raise IntegrityError("Trust policy predicate role mapping is not canonical.")
    for role, minimum in thresholds.items():
        role_keys = [key for key in keys if key.role == role]
        identities = (
            {key.actor_id for key in role_keys}
            if mode == "PRODUCTION"
            else {key.public_key for key in role_keys}
        )
        if len(role_keys) < minimum or len(identities) < minimum:
            raise IntegrityError("Trust policy threshold exceeds distinct configured signers.")

    return TrustPolicy(
        policy_bytes=policy_bytes,
        sha256=actual_sha256,
        document=document,
        keys=tuple(keys),
        thresholds=thresholds,
        predicate_roles=predicate_roles,
    )


def _predicate_qualifies(predicate_type: str, predicate: dict[str, Any]) -> bool:
    issued_at = _timestamp(predicate["issued_at"], "predicate.issued_at")
    if (
        predicate_type.endswith("/authority-authorization/v0.4")
        and _timestamp(predicate["expires_at"], "predicate.expires_at") < issued_at
    ):
        raise IntegrityError("Authority authorization expires before it is issued.")
    if predicate_type.endswith("/isolation/v0.4"):
        if _timestamp(predicate["completed_at"], "predicate.completed_at") < _timestamp(
            predicate["started_at"], "predicate.started_at"
        ):
            raise IntegrityError("Isolation attestation completes before it starts.")
        return (
            predicate["isolation_class"] == "EXTERNAL_SEALED"
            and predicate["network_mode"] == "DENY_ALL"
            and predicate["filesystem_mode"] == "IMMUTABLE_INPUT_ISOLATED_OUTPUT"
            and predicate["residual_state_detected"] is False
        )
    if predicate_type.endswith("/custody/v0.4"):
        chronological = _timestamp(predicate["sealed_at"], "predicate.sealed_at") < _timestamp(
            predicate["explorer_development_started_at"],
            "predicate.explorer_development_started_at",
        )
        return (
            chronological
            and predicate["independent_custody"]
            and predicate["sealed_before_explorer"]
            and predicate["hidden_case_count"] == 7
            and predicate["positive_case_count"] == 5
            and predicate["control_case_count"] == 2
            and not predicate["explorer_ground_truth_access"]
            and not predicate["evaluator_access"]
            and not predicate["directional_steering"]
        )
    if predicate_type.endswith("/trial-evaluation/v0.4"):
        bindings = predicate["run_bindings"]
        pairs = {(item["variant"], item["case_id"]) for item in bindings}
        run_ids = {item["run_id"] for item in bindings}
        variants = {item["variant"] for item in bindings}
        case_ids = {item["case_id"] for item in bindings}
        cartesian = {(variant, case_id) for variant in variants for case_id in case_ids}
        if (
            variants != TRIAL_VARIANTS
            or len(case_ids) != 7
            or pairs != cartesian
            or len(run_ids) != 35
        ):
            raise IntegrityError("Trial evaluation run bindings are not a unique 35-run matrix.")
        observed = predicate["observed"]
        if (
            observed["trusted_verified_positives"] > observed["claimed_verified_total"]
            or observed["false_verified_controls"] > observed["claimed_verified_total"]
            or observed["clean_replay_verified"] > observed["claimed_verified_total"]
        ):
            raise IntegrityError("Trial evaluation signed counts are internally inconsistent.")
        expected_gates = {
            "matrix_complete": len(bindings) == 35 and len(pairs) == 35 and len(run_ids) == 35,
            "positive_threshold_met": observed["trusted_verified_positives"] >= 3,
            "control_threshold_met": (
                observed["false_verified_controls"] == 0 and observed["false_verified_claims"] == 0
            ),
            "clean_replay_complete": (
                observed["clean_replay_verified"] == observed["claimed_verified_total"]
                and observed["false_verified_claims"] == 0
            ),
            "context_provenance_complete": observed["context_provenance_complete"],
            "inputs_immutable": (
                observed["target_snapshot_immutable"]
                and observed["hidden_inputs_immutable"]
                and observed["scoring_policy_immutable"]
            ),
        }
        for gate_name, expected in expected_gates.items():
            if predicate["gates"][gate_name] is not expected:
                raise IntegrityError(
                    "Trial evaluation gate does not match its signed observations.",
                    details={"gate": gate_name},
                )
        all_gates = all(predicate["gates"].values())
        if (predicate["status"] == "THRESHOLDS_MET") != all_gates:
            raise IntegrityError("Trial evaluation status does not match its complete gate vector.")
        return all_gates
    if predicate_type.endswith("/m0-certification/v0.4"):
        return predicate["decision"] == "M0_DEMONSTRATED"
    return True


def verify_dsse_statement(
    envelope_bytes: bytes,
    *,
    expected_predicate_type: str,
    trusted_keys: Sequence[TrustedEd25519Key],
    threshold: int,
    predicate_schema: str,
) -> VerifiedStatement:
    """Verify DSSE, in-toto Statement v1, strict predicate, role, time, and threshold."""

    expected_contract = PREDICATE_ROLES.get(expected_predicate_type)
    if expected_contract is None or expected_contract[1] != predicate_schema:
        raise UsageError("Predicate type and predicate schema are not a canonical pair.")
    expected_role = expected_contract[0]
    role_keys = tuple(key for key in trusted_keys if key.role == expected_role)
    if not role_keys:
        raise IntegrityError("No caller-trusted key has the required predicate role.")
    payload, parsed, signers = _decode_and_verify_dsse(
        envelope_bytes,
        expected_payload_type=DSSE_PAYLOAD_TYPE,
        trusted_keys=role_keys,
        threshold=threshold,
    )
    statement_fields = {"_type", "subject", "predicateType", "predicate"}
    if not isinstance(parsed, dict) or not statement_fields <= set(parsed):
        raise UsageError("Signed payload is not an in-toto Statement v1 object.")
    if parsed["_type"] != IN_TOTO_STATEMENT_TYPE:
        raise IntegrityError("Signed statement has the wrong in-toto statement type.")
    if parsed["predicateType"] != expected_predicate_type:
        raise IntegrityError("Signed statement has the wrong predicate type.")
    if not isinstance(parsed["subject"], list) or not isinstance(parsed["predicate"], dict):
        raise UsageError("Signed statement subject and predicate have invalid JSON types.")
    predicate = parsed["predicate"]
    validate_or_raise(predicate_schema, predicate)
    issued_at = _timestamp(predicate["issued_at"], "predicate.issued_at")
    qualifying = tuple(
        key
        for key in signers
        if key.status == "ACTIVE"
        and key.valid_from is not None
        and key.valid_until is not None
        and key.policy_valid_from is not None
        and key.policy_valid_until is not None
        and _timestamp(key.policy_valid_from, "policy.valid_from")
        <= issued_at
        <= _timestamp(key.policy_valid_until, "policy.valid_until")
        and _timestamp(key.valid_from, "key.valid_from")
        <= issued_at
        <= _timestamp(key.valid_until, "key.valid_until")
    )
    raw_count = len({key.public_key for key in qualifying})
    if raw_count < threshold:
        raise IntegrityError("Statement threshold is not met by active, time-valid identities.")
    modes = {key.trust_mode for key in qualifying}
    if len(modes) != 1 or None in modes:
        raise IntegrityError("Verified statement signers do not share one pinned trust mode.")
    mode = next(iter(modes))
    actor_count = len({key.actor_id for key in qualifying})
    if mode == "PRODUCTION" and actor_count < threshold:
        raise IntegrityError("Statement threshold is not met by active, time-valid identities.")
    policy_hashes = {key.policy_sha256 for key in qualifying}
    if len(policy_hashes) != 1 or None in policy_hashes:
        raise IntegrityError("Statement signers do not share one pinned trust policy.")
    if predicate["trust_policy_sha256"] != next(iter(policy_hashes)):
        raise IntegrityError("Predicate trust policy binding does not match its signer policy.")
    actor_ids = tuple(sorted({str(key.actor_id) for key in qualifying}))
    if predicate["issuer_actor_id"] not in actor_ids:
        raise IntegrityError("Predicate issuer_actor_id is not one of its verified signers.")
    semantic_qualifier = _predicate_qualifies(expected_predicate_type, predicate)
    return VerifiedStatement(
        payload_bytes=payload,
        payload_sha256=sha256_bytes(payload),
        statement=parsed,
        predicate=predicate,
        signer_fingerprints=tuple(sorted({key.fingerprint for key in qualifying})),
        signer_key_ids=tuple(sorted({str(key.keyid) for key in qualifying})),
        signer_actor_ids=actor_ids,
        signer_roles=tuple(sorted({str(key.role) for key in qualifying})),
        trust_mode=mode,
        production_qualified=mode == "PRODUCTION" and semantic_qualifier,
    )


__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "DSSE_PAE_PREFIX",
    "DSSE_VERSION",
    "IN_TOTO_STATEMENT_TYPE",
    "PREDICATE_ROLES",
    "TrustPolicy",
    "TrustedEd25519Key",
    "VerifiedStatement",
    "dsse_b64decode",
    "dsse_pae",
    "parse_strict_json",
    "load_trust_policy",
    "strict_b64decode",
    "verify_dsse_json_envelope",
    "verify_dsse_statement",
    "verify_ed25519",
]
