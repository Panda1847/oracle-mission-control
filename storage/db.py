"""SQLite-backed mission metadata store."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List


class Database:
    """Tiny SQLite wrapper used for enterprise metadata and artifact indexing."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._conn = self._connect()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _ensure_schema(self):
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mission_metadata (
                    mission_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_index (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    content_type TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def upsert_mission(self, mission_id: str, status: str, phase: str, payload_json: str):
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO mission_metadata (mission_id, status, phase, payload_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(mission_id) DO UPDATE SET
                  status=excluded.status,
                  phase=excluded.phase,
                  payload_json=excluded.payload_json
                """,
                (mission_id, status, phase, payload_json),
            )
            self._conn.commit()

    def add_artifact(self, mission_id: str, artifact_type: str, path: str, content_type: str):
        with self._lock:
            self._conn.execute(
                "INSERT INTO artifact_index (mission_id, artifact_type, path, content_type) VALUES (?, ?, ?, ?)",
                (mission_id, artifact_type, path, content_type),
            )
            self._conn.commit()

    def artifacts_for(self, mission_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT artifact_type, path, content_type FROM artifact_index WHERE mission_id = ? ORDER BY id ASC",
                (mission_id,),
            ).fetchall()
        return [{"artifact_type": row[0], "path": row[1], "content_type": row[2]} for row in rows]
