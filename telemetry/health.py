"""Health and readiness reporting for enterprise modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HealthStatus:
    component: str
    status: str
    details: Dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=_ts)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HealthMonitor:
    """Tracks component health without turning transient failures into global outages."""

    def __init__(self):
        self._components: Dict[str, HealthStatus] = {}
        self._lock = RLock()

    def report(self, component: str, status: str, details: Dict[str, Any] | None = None):
        with self._lock:
            self._components[component] = HealthStatus(component=component, status=status, details=dict(details or {}))

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            components = {name: status.to_dict() for name, status in self._components.items()}
        overall = "ok"
        if any(item["status"] == "down" for item in components.values()):
            overall = "degraded"
        return {"overall": overall, "components": components}


GLOBAL_HEALTH = HealthMonitor()

