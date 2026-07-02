"""TTL and confidence decay utilities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class TTLDecayPolicy:
    """Applies default TTL windows and confidence decay."""

    DEFAULT_TTL = {
        "host": 7 * 24 * 3600,
        "service": 14 * 24 * 3600,
        "finding": 30 * 24 * 3600,
        "cve": 30 * 24 * 3600,
    }

    def ttl_for(self, entity: str) -> int:
        return int(self.DEFAULT_TTL.get(entity, 14 * 24 * 3600))

    def expires_at(self, observed_at: datetime, ttl_seconds: int) -> datetime:
        return observed_at + timedelta(seconds=max(1, ttl_seconds))

    def decay(self, confidence: float, observed_at: datetime, ttl_seconds: int, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        elapsed = max(0.0, (now - observed_at).total_seconds())
        ratio = min(1.0, elapsed / max(ttl_seconds, 1))
        return round(max(0.05, confidence * (1.0 - (ratio * 0.65))), 4)

    def is_expired(self, observed_at: datetime, ttl_seconds: int, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return (now - observed_at).total_seconds() > max(1, ttl_seconds)
