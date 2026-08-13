from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from unasked.errors import IntegrityError, UsageError
from unasked.locking import exclusive_file_lock
from unasked.schemas import validate
from unasked.util import canonical_json, hash_json, require_identifier, utc_now

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
SCHEMA_VERSION = "0.1.0"
ACTOR_ROLES = frozenset(
    {
        "PRINCIPAL_INVESTIGATOR",
        "EXPLORER",
        "EXPERIMENT_PLANNER",
        "SANDBOX_EXECUTOR",
        "FALSIFIER",
        "INDEPENDENT_REPRODUCER",
        "DISCOVERY_AUTHORITY_KERNEL",
        "HUMAN_JUDGE",
        "SYSTEM",
    }
)
CAPABILITIES = frozenset(
    {
        "OBSERVE",
        "PROPOSE_CANDIDATE",
        "REQUEST_EXPERIMENT",
        "EXECUTE_SANDBOX",
        "SUBMIT_EVIDENCE",
        "CHALLENGE",
        "REPLAY",
        "AUTHORIZE_VERDICT",
        "PUBLISH",
    }
)


@contextmanager
def _exclusive_ledger_lock(path: Path) -> Iterator[None]:
    """Serialize a ledger mutation across threads and processes."""

    with exclusive_file_lock(path.with_name(f"{path.name}.lock")):
        yield


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    """The result of checking every byte and link in an event ledger."""

    valid: bool
    entries: int
    last_hash: str | None
    error: str | None = None
    line: int | None = None
    sequence: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries": self.entries,
            "last_hash": self.last_hash,
            "error": self.error,
            "line": self.line,
            "sequence": self.sequence,
            "details": dict(self.details),
        }

    def raise_for_error(self) -> None:
        if not self.valid:
            raise IntegrityError(
                self.error or "The event ledger failed integrity verification.",
                details=self.to_dict(),
            )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate object key: {key!r}")
        value[key] = item
    return value


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_json_value(value: Any, *, location: str = "payload") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise UsageError(f"{location} contains a non-finite number.")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, location=f"{location}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise UsageError(f"{location} contains a non-string object key.")
            _validate_json_value(item, location=f"{location}.{key}")
        return
    raise UsageError(f"{location} is not JSON-serializable: {type(value).__name__}.")


def _validate_timestamp(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("occurred_at must be a non-empty string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("occurred_at must include a UTC offset")


class EventLedger:
    """A canonical JSONL, append-only, hash-chained event ledger.

    The class intentionally has no update, truncate, or delete operation. Existing
    content is verified before each append, and the new line is opened with OS-level
    append semantics so construction never truncates an existing ledger.
    """

    def __init__(self, path: str | Path, *, run_id: str | None = None) -> None:
        self.path = Path(path)
        self.run_id = require_identifier(run_id, "run_id") if run_id is not None else None

    def _failure(
        self,
        message: str,
        *,
        entries: int,
        last_hash: str | None,
        line: int | None = None,
        sequence: int | None = None,
        **details: Any,
    ) -> LedgerVerification:
        return LedgerVerification(
            valid=False,
            entries=entries,
            last_hash=last_hash,
            error=message,
            line=line,
            sequence=sequence,
            details=details,
        )

    def _scan(self) -> tuple[LedgerVerification, list[dict[str, Any]]]:
        if not self.path.exists():
            return LedgerVerification(True, 0, None), []
        if not self.path.is_file():
            report = self._failure(
                "The event ledger path is not a regular file.",
                entries=0,
                last_hash=None,
                path=str(self.path),
            )
            return report, []

        try:
            raw_ledger = self.path.read_bytes()
        except OSError as exc:
            report = self._failure(
                "The event ledger could not be read.",
                entries=0,
                last_hash=None,
                path=str(self.path),
                reason=str(exc),
            )
            return report, []

        if not raw_ledger:
            return LedgerVerification(True, 0, None), []
        if not raw_ledger.endswith(b"\n"):
            line = raw_ledger.count(b"\n") + 1
            report = self._failure(
                "The final ledger entry is incomplete (missing newline).",
                entries=max(0, line - 1),
                last_hash=None,
                line=line,
            )
            return report, []

        raw_lines = raw_ledger.split(b"\n")[:-1]
        records: list[dict[str, Any]] = []
        previous_hash: str | None = None

        for index, raw_line in enumerate(raw_lines):
            line_number = index + 1
            if not raw_line:
                report = self._failure(
                    "Blank lines are not permitted in an event ledger.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                )
                return report, records

            try:
                record = json.loads(
                    raw_line.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_non_finite,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                report = self._failure(
                    "The ledger entry is not valid, unambiguous UTF-8 JSON.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    reason=str(exc),
                )
                return report, records

            if not isinstance(record, dict):
                report = self._failure(
                    "Each ledger entry must be a JSON object.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                )
                return report, records

            if raw_line != canonical_json(record):
                report = self._failure(
                    "The ledger entry is not encoded as canonical JSON.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                )
                return report, records

            required = {
                "schema_version",
                "event_id",
                "run_id",
                "sequence",
                "occurred_at",
                "event_type",
                "actor",
                "payload",
                "artifact_refs",
                "previous_event_hash",
                "event_hash",
            }
            missing = sorted(required.difference(record))
            if missing:
                report = self._failure(
                    "The ledger entry is missing required fields.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    missing=missing,
                )
                return report, records

            sequence = record["sequence"]
            if isinstance(sequence, bool) or sequence != index:
                report = self._failure(
                    "The ledger sequence is not contiguous from zero.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=sequence if isinstance(sequence, int) else None,
                    expected=index,
                    actual=sequence,
                )
                return report, records

            if record["previous_event_hash"] != previous_hash:
                report = self._failure(
                    "The ledger hash chain is broken at previous_event_hash.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    expected=previous_hash,
                    actual=record["previous_event_hash"],
                )
                return report, records

            try:
                if record["schema_version"] != SCHEMA_VERSION:
                    raise ValueError("unsupported event schema_version")
                require_identifier(record["event_id"], "event_id")
                require_identifier(record["run_id"], "run_id")
                _validate_timestamp(record["occurred_at"])
            except (TypeError, ValueError, UsageError) as exc:
                report = self._failure(
                    "The ledger entry has invalid identity or timestamp fields.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    reason=str(exc),
                )
                return report, records

            event_hash = record["event_hash"]
            if not isinstance(event_hash, str) or not SHA256_RE.fullmatch(event_hash):
                report = self._failure(
                    "event_hash is not a lowercase SHA-256 digest.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    actual=event_hash,
                )
                return report, records

            hash_input = {key: value for key, value in record.items() if key != "event_hash"}
            expected_hash = hash_json(hash_input)
            if event_hash != expected_hash:
                report = self._failure(
                    "The ledger event hash does not match its canonical content.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    expected=expected_hash,
                    actual=event_hash,
                )
                return report, records

            schema_issues = validate("event", record)
            if schema_issues:
                report = self._failure(
                    "The ledger entry fails the event schema.",
                    entries=len(records),
                    last_hash=previous_hash,
                    line=line_number,
                    sequence=index,
                    errors=[issue.to_dict() for issue in schema_issues],
                )
                return report, records

            records.append(record)
            previous_hash = event_hash

        return LedgerVerification(True, len(records), previous_hash), records

    def verify(self, *, raise_on_error: bool = False) -> LedgerVerification:
        """Verify canonical encoding, sequence, and the complete hash chain."""

        report, _ = self._scan()
        if raise_on_error:
            report.raise_for_error()
        return report

    def verify_or_raise(self) -> LedgerVerification:
        return self.verify(raise_on_error=True)

    def append(
        self,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        actor: str | Mapping[str, Any] = "system",
        role: str = "SYSTEM",
        capabilities: Sequence[str] = (),
        run_id: str | None = None,
        occurred_at: str | None = None,
        timestamp: str | None = None,
        artifact_refs: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        """Append one event after verifying the entire existing ledger.

        ``timestamp`` is accepted as an input alias for the schema field
        ``occurred_at``. Actor strings are normalized into the schema's actor object.
        """

        if not isinstance(event_type, str) or not EVENT_TYPE_RE.fullmatch(event_type):
            raise UsageError("event_type must be an uppercase event identifier.")
        selected_run_id = run_id if run_id is not None else self.run_id
        if selected_run_id is None:
            raise UsageError("run_id is required on EventLedger or append().")
        selected_run_id = require_identifier(selected_run_id, "run_id")

        if occurred_at is not None and timestamp is not None:
            raise UsageError("Specify occurred_at or timestamp, not both.")
        selected_time = occurred_at or timestamp or utc_now()
        try:
            _validate_timestamp(selected_time)
        except (TypeError, ValueError) as exc:
            raise UsageError("occurred_at must be an offset-aware ISO-8601 timestamp.") from exc

        if isinstance(actor, str):
            if not actor:
                raise UsageError("actor must be a non-empty string.")
            actor_value: dict[str, Any] = {
                "actor_id": actor,
                "role": role,
                "capabilities": list(capabilities),
            }
        elif isinstance(actor, Mapping):
            actor_value = dict(actor)
            actor_value.setdefault("role", role)
            actor_value.setdefault("capabilities", list(capabilities))
        else:
            raise UsageError("actor must be a string or JSON object.")

        if set(actor_value) != {"actor_id", "role", "capabilities"}:
            raise UsageError("actor must contain exactly actor_id, role, and capabilities.")
        try:
            require_identifier(actor_value["actor_id"], "actor_id")
        except (TypeError, UsageError) as exc:
            raise UsageError("actor_id must be a valid identifier.") from exc
        if actor_value["role"] not in ACTOR_ROLES:
            raise UsageError("actor role is not recognized.")
        actor_capabilities = actor_value["capabilities"]
        if (
            not isinstance(actor_capabilities, list)
            or any(item not in CAPABILITIES for item in actor_capabilities)
            or len(set(actor_capabilities)) != len(actor_capabilities)
        ):
            raise UsageError("actor capabilities must be unique recognized capability names.")

        if payload is not None and not isinstance(payload, Mapping):
            raise UsageError("payload must be a JSON object.")
        payload_value = dict(payload or {})
        if isinstance(artifact_refs, (str, bytes)):
            raise UsageError("artifact_refs must be a sequence of JSON objects.")
        try:
            refs_value = [dict(reference) for reference in artifact_refs]
        except (TypeError, ValueError) as exc:
            raise UsageError("artifact_refs must be a sequence of JSON objects.") from exc
        _validate_json_value(actor_value, location="actor")
        _validate_json_value(payload_value)
        _validate_json_value(refs_value, location="artifact_refs")

        with _exclusive_ledger_lock(self.path):
            report, records = self._scan()
            report.raise_for_error()
            if records and any(record["run_id"] != selected_run_id for record in records):
                raise UsageError("All events in a ledger must belong to the same run_id.")
            previous_hash = records[-1]["event_hash"] if records else None
            entry: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "event_id": f"EVT-{len(records):08d}",
                "run_id": selected_run_id,
                "sequence": len(records),
                "occurred_at": selected_time,
                "event_type": event_type,
                "actor": actor_value,
                "payload": payload_value,
                "artifact_refs": refs_value,
                "previous_event_hash": previous_hash,
            }
            entry["event_hash"] = hash_json(entry)
            encoded = canonical_json(entry) + b"\n"

            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            descriptor = os.open(self.path, flags, 0o600)
            with os.fdopen(descriptor, "ab", buffering=0) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())

        return json.loads(canonical_json(entry).decode("utf-8"))

    append_event = append

    def read_all(self) -> list[dict[str, Any]]:
        report, records = self._scan()
        report.raise_for_error()
        return records

    def iter_events(self) -> Iterator[dict[str, Any]]:
        yield from self.read_all()

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self.iter_events()

    def __len__(self) -> int:
        report = self.verify(raise_on_error=True)
        return report.entries

    @property
    def last_hash(self) -> str | None:
        return self.verify(raise_on_error=True).last_hash
