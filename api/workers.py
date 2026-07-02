"""Worker control-plane serializers."""

from __future__ import annotations

from typing import Any, Dict, List


def worker_snapshot(dispatcher) -> List[Dict[str, Any]]:
    if dispatcher is None or not getattr(dispatcher, "registry", None):
        return []
    items: List[Dict[str, Any]] = []
    for record in dispatcher.registry.all().values():
        items.append(
            {
                "worker_id": record.worker_id,
                "endpoint": record.endpoint,
                "capabilities": list(record.capabilities),
                "transport": record.transport,
                "role": record.role,
                "health_score": round(record.health_score, 3),
                "inflight_jobs": record.inflight_jobs,
                "metadata": dict(record.metadata),
            }
        )
    return items

