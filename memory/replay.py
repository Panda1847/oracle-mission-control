"""Replay artifact storage for mission iterations."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


class ReplayStore:
    """Stores per-iteration replay artifacts for audit and debugging."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create(self, mission_id: str, payload: Dict[str, Any], *, branch: str = "") -> Path:
        replay_id = str(payload.get("replay_id") or uuid4().hex)
        safe_branch = (branch or "iteration").replace("/", "_").replace(" ", "_")
        path = self.base_dir / f"{mission_id}-{_ts()}-{safe_branch}-{replay_id[:12]}.json"
        body = dict(payload)
        body.setdefault("replay_id", replay_id)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True, default=str), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def list(self, mission_id: str) -> List[Path]:
        return sorted(self.base_dir.glob(f"{mission_id}-*.json"))

    def latest(self, mission_id: str) -> Path | None:
        artifacts = self.list(mission_id)
        if not artifacts:
            return None
        return artifacts[-1]

    def find(self, mission_id: str, replay_id: str) -> Path | None:
        needle = str(replay_id or "").strip().lower()
        if not needle:
            return self.latest(mission_id)
        for path in reversed(self.list(mission_id)):
            loaded = self.load(path)
            candidate = str(loaded.get("replay_id", "") or "").strip().lower()
            if candidate.startswith(needle):
                return path
        return None

    def load(self, path: str | Path) -> Dict[str, Any]:
        return json.loads(Path(path).read_text(encoding="utf-8"))
