"""Artifact persistence helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from core.orchestrator.artifact_router import ArtifactRouter
from .db import Database


class ArtifactStore:
    """Coordinates disk artifacts with SQLite indexing."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.router = ArtifactRouter(self.base_dir / "files")
        self.db = Database(self.base_dir / "artifacts.sqlite3")

    def save(self, mission_id: str, artifact_type: str, name: str, content: Any, *, extension: str = "", content_type: str = "text/plain") -> Dict[str, Any]:
        record = self.router.route(artifact_type, name, content, extension=extension, content_type=content_type)
        self.db.add_artifact(mission_id, artifact_type, record.path, record.content_type)
        return record.to_dict()

    def list(self, mission_id: str) -> List[Dict[str, Any]]:
        return self.db.artifacts_for(mission_id)

