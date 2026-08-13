from __future__ import annotations

import json
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import pytest

from unasked.errors import IntegrityError
from unasked.ledger import EventLedger
from unasked.schemas import validate_or_raise
from unasked.util import canonical_json, hash_json


def _append_from_process(path: str, value: int) -> None:
    EventLedger(path, run_id="run-processes").append("EVENT_RECORDED", {"value": value})


def test_ledger_appends_a_canonical_hash_chain_and_reopens(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = EventLedger(path, run_id="run-001")

    first = ledger.append(
        "RUN_CREATED",
        {"target": "abc123"},
        actor="explorer-1",
        role="EXPLORER",
    )
    second = ledger.append(
        "OBSERVATION_RECORDED",
        {"observation_id": "O-1"},
        actor="explorer-1",
        role="EXPLORER",
        capabilities=["OBSERVE"],
    )

    assert first["sequence"] == 0
    assert first["previous_event_hash"] is None
    assert first["event_hash"] == hash_json(
        {key: value for key, value in first.items() if key != "event_hash"}
    )
    assert second["sequence"] == 1
    assert second["previous_event_hash"] == first["event_hash"]
    assert second["actor"] == {
        "actor_id": "explorer-1",
        "role": "EXPLORER",
        "capabilities": ["OBSERVE"],
    }
    validate_or_raise("event", first)
    validate_or_raise("event", second)
    assert path.read_bytes().splitlines()[0] == canonical_json(first)

    report = ledger.verify()
    assert report.valid
    assert report.entries == 2
    assert report.last_hash == second["event_hash"]

    reopened = EventLedger(path, run_id="run-001")
    third = reopened.append(
        "HYPOTHESIS_PROPOSED",
        {"hypothesis_id": "H-1"},
        actor="explorer-1",
        role="EXPLORER",
    )
    assert third["sequence"] == 2
    assert third["previous_event_hash"] == second["event_hash"]
    assert len(reopened) == 3


def test_ledger_reports_tampering_location_and_refuses_to_append(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = EventLedger(path, run_id="run-002")
    ledger.append("RUN_CREATED", {"value": "original"})
    ledger.append("RUN_STARTED", {"value": 2})

    lines = path.read_bytes().splitlines()
    first = json.loads(lines[0])
    first["payload"]["value"] = "tampered"
    path.write_bytes(canonical_json(first) + b"\n" + lines[1] + b"\n")

    report = ledger.verify()
    assert not report.valid
    assert report.line == 1
    assert report.sequence == 0
    assert "hash" in (report.error or "").lower()
    with pytest.raises(IntegrityError) as error:
        ledger.append("MUST_NOT_APPEND", {})
    assert error.value.details["line"] == 1
    assert len(path.read_bytes().splitlines()) == 2


def test_ledger_rejects_noncanonical_or_incomplete_jsonl(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = EventLedger(path, run_id="run-003")
    event = ledger.append("RUN_CREATED", {})

    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    report = ledger.verify()
    assert not report.valid
    assert report.line == 1
    assert "canonical" in (report.error or "").lower()

    path.write_bytes(canonical_json(event))
    report = ledger.verify()
    assert not report.valid
    assert report.line == 1
    assert "incomplete" in (report.error or "").lower()


def test_ledger_rejects_rehashed_events_that_violate_the_event_schema(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = EventLedger(path, run_id="run-schema")
    event = ledger.append("RUN_CREATED", {})
    event["actor"]["role"] = "UNRECOGNIZED_ROLE"
    event["event_hash"] = hash_json(
        {key: value for key, value in event.items() if key != "event_hash"}
    )
    path.write_bytes(canonical_json(event) + b"\n")

    report = ledger.verify()
    assert report.valid is False
    assert report.line == 1
    assert "schema" in (report.error or "").lower()


def test_ledger_exposes_no_overwrite_or_delete_api(tmp_path) -> None:
    ledger = EventLedger(tmp_path / "events.jsonl", run_id="run-004")
    assert not hasattr(ledger, "overwrite")
    assert not hasattr(ledger, "delete")
    assert not hasattr(ledger, "truncate")


def test_ledger_serializes_concurrent_thread_appends(tmp_path) -> None:
    path = tmp_path / "thread-events.jsonl"

    def append(value: int) -> None:
        EventLedger(path, run_id="run-threads").append("EVENT_RECORDED", {"value": value})

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(append, range(32)))

    events = EventLedger(path, run_id="run-threads").read_all()
    assert [event["sequence"] for event in events] == list(range(32))
    assert {event["payload"]["value"] for event in events} == set(range(32))


def test_ledger_serializes_concurrent_process_appends(tmp_path) -> None:
    path = tmp_path / "process-events.jsonl"
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_append_from_process, args=(str(path), value)) for value in range(8)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    events = EventLedger(path, run_id="run-processes").read_all()
    assert [event["sequence"] for event in events] == list(range(8))
    assert {event["payload"]["value"] for event in events} == set(range(8))
