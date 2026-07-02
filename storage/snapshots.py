"""Mission snapshot persistence."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


class SnapshotStore:
    """Stores replayable mission snapshots without replacing the live mission file."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create(self, mission_id: str, payload: Dict[str, Any], *, tag: str = "") -> Path:
        suffix = f"-{tag}" if tag else ""
        path = self.base_dir / f"{mission_id}-{_ts()}{suffix}.json"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def list(self, mission_id: str) -> List[Path]:
        return sorted(self.base_dir.glob(f"{mission_id}-*.json"))
