"""Worker registry and selection."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Dict, Optional

from .heartbeat import HeartbeatState, compute_health_score


@dataclass
class WorkerRecord:
    worker_id: str
    endpoint: str
    capabilities: list[str]
    transport: str = "http"
    role: str = "remote"
    metadata: dict = field(default_factory=dict)
    heartbeat: HeartbeatState = field(default_factory=lambda: HeartbeatState(last_seen=time.time()))
    health_score: float = 1.0
    inflight_jobs: int = 0

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities or "*" in self.capabilities


class WorkerRegistry:
    """Tracks worker registration, heartbeat, and health score."""

    def __init__(self, heartbeat_timeout_seconds: int = 45):
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._workers: Dict[str, WorkerRecord] = {}

    def register(
        self,
        worker_id: str,
        endpoint: str,
        capabilities: list[str],
        transport: str = "http",
        role: str = "remote",
        metadata: Optional[dict] = None,
    ) -> WorkerRecord:
        record = WorkerRecord(
            worker_id=worker_id,
            endpoint=endpoint,
            capabilities=list(capabilities or ["*"]),
            transport=transport,
            role=role,
            metadata=dict(metadata or {}),
        )
        self._workers[worker_id] = record
        self.touch(worker_id)
        return record

    def get(self, worker_id: str) -> Optional[WorkerRecord]:
        return self._workers.get(worker_id)

    def all(self) -> Dict[str, WorkerRecord]:
        return dict(self._workers)

    def touch(self, worker_id: str) -> Optional[WorkerRecord]:
        record = self._workers.get(worker_id)
        if not record:
            return None
        record.heartbeat.last_seen = time.time()
        record.health_score = compute_health_score(record.heartbeat, self.heartbeat_timeout_seconds)
        return record

    def acknowledge(self, worker_id: str):
        record = self.touch(worker_id)
        if not record:
            return
        record.heartbeat.ack_count += 1
        record.inflight_jobs += 1
        record.health_score = compute_health_score(record.heartbeat, self.heartbeat_timeout_seconds)

    def complete(self, worker_id: str, success: bool):
        record = self.touch(worker_id)
        if not record:
            return
        record.heartbeat.completed_count += 1
        if success:
            record.heartbeat.success_count += 1
        else:
            record.heartbeat.failure_count += 1
        record.inflight_jobs = max(0, record.inflight_jobs - 1)
        record.health_score = compute_health_score(record.heartbeat, self.heartbeat_timeout_seconds)

    def healthiest(self, capability: str) -> Optional[WorkerRecord]:
        candidates = [record for record in self._workers.values() if record.supports(capability)]
        if not candidates:
            return None
        candidates.sort(key=lambda record: (record.health_score, record.role != "local"), reverse=True)
        return candidates[0]
