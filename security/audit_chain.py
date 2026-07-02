"""Immutable actor audit log."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Dict


class ActorAuditChain:
    """Append-only actor audit log with hash chaining."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = ""

    def log(self, event: str, actor: str, role: str, session_id: str, payload: Dict[str, Any]):
        record = {
            "event": event,
            "actor": actor,
            "role": role,
            "session_id": session_id,
            "payload": payload,
            "prev_hash": self._last_hash,
        }
        material = json.dumps(record, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((self._last_hash + material).encode("utf-8")).hexdigest()
        record["hash"] = digest
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            self._last_hash = digest

    def verify_chain(self) -> bool:
        """Recompute and verify the full on-disk hash chain."""
        if not self.path.exists():
            return True
        prev_hash = ""
        last_hash = ""
        with self._lock:
            with self.path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except Exception:
                        return False
                    stored_hash = str(record.get("hash", ""))
                    stored_prev = str(record.get("prev_hash", ""))
                    if stored_prev != prev_hash:
                        return False
                    material_record = dict(record)
                    material_record.pop("hash", None)
                    material = json.dumps(material_record, sort_keys=True, separators=(",", ":"))
                    expected = hashlib.sha256((prev_hash + material).encode("utf-8")).hexdigest()
                    if stored_hash != expected:
                        return False
                    prev_hash = stored_hash
                    last_hash = stored_hash
            self._last_hash = last_hash
        return True
