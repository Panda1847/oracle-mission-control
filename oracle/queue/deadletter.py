"""Dead-letter support for queue processing failures."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DeadLetterRecord:
    topic: str
    payload: Dict[str, Any]
    reason: str
    failed_at: str = field(default_factory=_ts)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DeadLetterQueue:
    """File-backed dead-letter queue so one broken consumer does not halt the framework."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self._items: List[DeadLetterRecord] = []
        self._lock = RLock()

    def add(self, topic: str, payload: Dict[str, Any], reason: str) -> DeadLetterRecord:
        record = DeadLetterRecord(topic=topic, payload=dict(payload or {}), reason=str(reason))
        with self._lock:
            self._items.append(record)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        return record

    def items(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [item.to_dict() for item in self._items]
