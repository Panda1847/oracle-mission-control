"""Evidence provenance helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
from typing import Any, Dict


class ProvenanceBuilder:
    """Creates provenance records for evidence with persisted hash chaining."""

    def __init__(self, state_path: str | Path | None = None):
        self.state_path = Path(state_path) if state_path else None
        self._lock = threading.RLock()
        self._last_hash_by_mission: Dict[str, str] = {}
        if self.state_path is not None:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def build(self, source_plugin: str, mission_id: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        payload = dict(payload or {})
        with self._lock:
            prev = self._last_hash_by_mission.get(mission_id, "")
            material = json.dumps(
                {
                    "source_plugin": source_plugin,
                    "mission_id": mission_id,
                    "payload": payload,
                    "timestamp": now,
                    "prev_hash": prev,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            digest = hashlib.sha256((prev + material).encode("utf-8")).hexdigest()
            self._last_hash_by_mission[mission_id] = digest
            record = {
                "source_plugin": source_plugin,
                "mission_id": mission_id,
                "payload": payload,
                "timestamp": now,
                "prev_hash": prev,
                "hash": digest,
            }
            self._persist(record)
            return record

    def _persist(self, record: Dict[str, Any]):
        if self.state_path is None:
            return
        with self.state_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def _load(self):
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            with self.state_path.open("r", encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    mission_id = str(data.get("mission_id", ""))
                    digest = str(data.get("hash", ""))
                    if mission_id and digest:
                        self._last_hash_by_mission[mission_id] = digest
        except Exception:
            # Corrupt provenance history should not break runtime collection.
            return

    def last_hash(self, mission_id: str) -> str:
        return str(self._last_hash_by_mission.get(mission_id, ""))

    def summary(self, mission_id: str) -> Dict[str, Any]:
        return {
            "mission_id": mission_id,
            "last_hash": self.last_hash(mission_id),
        }
