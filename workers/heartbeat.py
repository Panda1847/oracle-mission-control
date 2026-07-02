"""Heartbeat and health score utilities."""

from __future__ import annotations

from dataclasses import dataclass
import time


@dataclass
class HeartbeatState:
    last_seen: float
    success_count: int = 0
    failure_count: int = 0
    ack_count: int = 0
    completed_count: int = 0


def compute_health_score(state: HeartbeatState, timeout_seconds: int = 45) -> float:
    now = time.time()
    stale_seconds = max(0.0, now - state.last_seen)
    freshness = max(0.0, 1.0 - (stale_seconds / max(timeout_seconds, 1)))
    total_runs = state.success_count + state.failure_count
    success_rate = (state.success_count / total_runs) if total_runs else 1.0
    ack_factor = min(1.0, state.ack_count / max(state.completed_count or 1, 1))
    return round((freshness * 0.45) + (success_rate * 0.4) + (ack_factor * 0.15), 4)

