"""Thread-safe in-memory event stream used by the enterprise control plane."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable, Deque, Dict, List, Optional
from uuid import uuid4


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EventMessage:
    topic: str
    payload: Dict[str, Any]
    trace_id: str
    created_at: str = field(default_factory=_ts)
    event_id: str = field(default_factory=lambda: uuid4().hex)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventStream:
    """Stores recent events for replay, dashboards, and audit-style inspection."""

    def __init__(self, max_events: int = 2000):
        self.max_events = max_events
        self._events: Deque[EventMessage] = deque(maxlen=max_events)
        self._subs: Dict[str, List[Callable[[EventMessage], None]]] = {}
        self._lock = RLock()

    def publish(self, topic: str, payload: Dict[str, Any], trace_id: str) -> EventMessage:
        message = EventMessage(topic=topic, payload=dict(payload or {}), trace_id=trace_id)
        with self._lock:
            self._events.append(message)
            subscribers = list(self._subs.get(topic, [])) + list(self._subs.get("*", []))
        for callback in subscribers:
            callback(message)
        return message

    def subscribe(self, topic: str, callback: Callable[[EventMessage], None]):
        with self._lock:
            self._subs.setdefault(topic, []).append(callback)

    def timeline(self, topic: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        if topic:
            events = [event for event in events if event.topic == topic]
        return [event.to_dict() for event in events[-limit:]]

    def latest(self, topic: Optional[str] = None) -> Optional[Dict[str, Any]]:
        timeline = self.timeline(topic=topic, limit=1)
        return timeline[-1] if timeline else None
