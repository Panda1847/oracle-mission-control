"""Minimal trace and span recorder."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterator, List
from uuid import uuid4


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceSpan:
    trace_id: str
    name: str
    started_at: str = field(default_factory=_ts)
    ended_at: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TraceRecorder:
    """Captures spans and point-in-time events for diagnostics and replay."""

    def __init__(self):
        self._spans: List[TraceSpan] = []
        self._events: List[Dict[str, Any]] = []
        self._lock = RLock()

    def new_trace_id(self, prefix: str = "trace") -> str:
        return f"{prefix}-{uuid4().hex}"

    @contextmanager
    def span(self, name: str, trace_id: str | None = None, **attributes) -> Iterator[str]:
        span = TraceSpan(trace_id=trace_id or self.new_trace_id(name), name=name, attributes=dict(attributes))
        try:
            yield span.trace_id
        except Exception as exc:
            span.status = f"error:{type(exc).__name__}"
            raise
        finally:
            span.ended_at = _ts()
            with self._lock:
                self._spans.append(span)

    def record_event(self, trace_id: str, name: str, payload: Dict[str, Any]):
        with self._lock:
            self._events.append(
                {
                    "trace_id": trace_id,
                    "name": name,
                    "payload": dict(payload or {}),
                    "ts": _ts(),
                }
            )

    def snapshot(self) -> Dict[str, List[Dict[str, Any]]]:
        with self._lock:
            return {
                "spans": [span.to_dict() for span in self._spans[-500:]],
                "events": list(self._events[-1000:]),
            }


GLOBAL_TRACES = TraceRecorder()

