"""Artifact routing for reports, bundles, exports, and mission side effects."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ArtifactRecord:
    artifact_type: str
    name: str
    path: str
    relative_path: str
    content_type: str
    created_at: str = field(default_factory=_ts)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ArtifactRouter:
    """Stores artifacts on disk and exposes them to reports and the dashboard."""

    def __init__(self, base_dir: str | Path | None = None):
        root = Path(base_dir or (Path.cwd() / ".oracle-artifacts"))
        root.mkdir(parents=True, exist_ok=True)
        self.base_dir = root

    def route(self, artifact_type: str, name: str, content: Any, *, extension: str = "", content_type: str = "text/plain") -> ArtifactRecord:
        target_dir = self.base_dir / artifact_type
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{name}{extension}" if extension else name
        path = target_dir / filename
        if isinstance(content, (dict, list)):
            path.write_text(json.dumps(content, indent=2, sort_keys=True), encoding="utf-8")
            content_type = "application/json"
        elif isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(str(content), encoding="utf-8")
        return ArtifactRecord(
            artifact_type=artifact_type,
            name=filename,
            path=str(path),
            relative_path=str(path.relative_to(self.base_dir)),
            content_type=content_type,
        )

    def list_artifacts(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for path in sorted(self.base_dir.rglob("*")):
            if path.is_dir():
                continue
            artifact_type = path.parent.relative_to(self.base_dir).parts[0] if path.parent != self.base_dir else "root"
            items.append(
                ArtifactRecord(
                    artifact_type=artifact_type,
                    name=path.name,
                    path=str(path),
                    relative_path=str(path.relative_to(self.base_dir)),
                    content_type="application/octet-stream" if path.suffix not in {".json", ".txt", ".md", ".html", ".pdf"} else "text/plain",
                ).to_dict()
            )
        return items

    def latest(self, artifact_type: str) -> Dict[str, Any] | None:
        items = [item for item in self.list_artifacts() if item["artifact_type"] == artifact_type]
        return items[-1] if items else None

    def resolve(self, relative_path: str) -> Path | None:
        candidate = (self.base_dir / str(relative_path or "")).resolve()
        try:
            candidate.relative_to(self.base_dir.resolve())
        except ValueError:
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        return candidate
