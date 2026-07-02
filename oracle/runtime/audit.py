from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


@dataclass
class AuditConfig:
    path: Path


class AuditLogger:
    """
    Append-only JSONL audit log with hash chaining for tamper-evidence.
    Each record includes: ts, seq, prev_hash, hash, and the event payload.
    """

    def __init__(self, cfg: AuditConfig):
        self.path = cfg.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = self._load_last_hash(self.path)

    def _load_last_hash(self, path: Path) -> str:
        try:
            if not path.exists():
                return ""
            # Best-effort: read tail line for hash.
            last = ""
            with path.open("rb") as f:
                try:
                    f.seek(-8192, 2)
                except Exception:
                    f.seek(0)
                chunk = f.read().decode("utf-8", errors="ignore")
                lines = [ln for ln in chunk.splitlines() if ln.strip()]
                if lines:
                    last = lines[-1]
            if last:
                obj = json.loads(last)
                h = obj.get("hash") or ""
                return h if isinstance(h, str) else ""
        except Exception:
            pass
        return ""

    @property
    def last_hash(self) -> str:
        return self._prev_hash

    def log(self, event_type: str, payload: Dict[str, Any]):
        rec: Dict[str, Any] = {
            "ts": _utc_ts(),
            "seq": None,  # filled under lock
            "event": event_type,
            "payload": payload,
            "prev_hash": None,  # filled under lock
        }

        with self._lock:
            self._seq += 1
            rec["seq"] = self._seq
            rec["prev_hash"] = self._prev_hash

            material = _canonical_json(rec)
            h = hashlib.sha256((self._prev_hash + material).encode("utf-8")).hexdigest()
            rec["hash"] = h

            line = _canonical_json(rec) + "\n"
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()

            self._prev_hash = h
        return rec
