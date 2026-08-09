from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class DerivedIndex:
    """Rebuildable lookup index. JSON/JSONL evidence remains the source of truth."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    target_commit TEXT NOT NULL,
                    protocol_hash TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    current_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, candidate_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                """
            )

    def upsert_run(self, run: dict[str, Any]) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs(run_id, created_at, target_commit, protocol_hash, status)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                  status=excluded.status,
                  protocol_hash=excluded.protocol_hash
                """,
                (
                    run["run_id"],
                    run["created_at"],
                    run["target_commit"],
                    run["protocol_hash"],
                    run["status"],
                ),
            )

    def upsert_candidate(
        self, *, run_id: str, candidate_id: str, state: str, updated_at: str
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO candidates(candidate_id, run_id, current_state, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id, candidate_id) DO UPDATE SET
                  current_state=excluded.current_state,
                  updated_at=excluded.updated_at
                """,
                (candidate_id, run_id, state, updated_at),
            )

    def list_runs(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM runs ORDER BY created_at, run_id").fetchall()
        return [dict(row) for row in rows]

    def list_candidates(self, run_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM candidates WHERE run_id=? ORDER BY candidate_id", (run_id,)
            ).fetchall()
        return [dict(row) for row in rows]
