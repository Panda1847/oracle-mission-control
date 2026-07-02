"""Operator session ownership persistence."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4


@dataclass
class OperatorSession:
    session_id: str
    username: str
    role: str
    mission_id: str


class OperatorSessionStore:
    """Simple JSON-backed session ownership store."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, OperatorSession] = {}
        self._load()

    def create(self, username: str, role: str, mission_id: str) -> OperatorSession:
        session = OperatorSession(session_id=uuid4().hex, username=username, role=role, mission_id=mission_id)
        self._sessions[session.session_id] = session
        self._save()
        return session

    def get(self, session_id: str) -> Optional[OperatorSession]:
        return self._sessions.get(session_id)

    def owns(self, session_id: str, username: str) -> bool:
        session = self.get(session_id)
        return bool(session and session.username == username)

    def _load(self):
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text() or "{}")
        for session_id, payload in data.items():
            self._sessions[session_id] = OperatorSession(**payload)

    def _save(self):
        self.path.write_text(json.dumps({sid: asdict(session) for sid, session in self._sessions.items()}, indent=2))

