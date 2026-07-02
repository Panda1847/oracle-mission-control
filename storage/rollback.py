"""Rollback helpers built on top of mission snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .snapshots import SnapshotStore


class RollbackManager:
    """Restores the most recent compatible snapshot path for operator-driven recovery."""

    def __init__(self, snapshot_store: SnapshotStore):
        self.snapshot_store = snapshot_store

    def latest(self, mission_id: str) -> Optional[Path]:
        items = self.snapshot_store.list(mission_id)
        return items[-1] if items else None

