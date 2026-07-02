"""JWT-style operator auth and role checks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


ROLE_PERMISSIONS = {
    "admin": {"approve", "observe", "operate", "audit"},
    "analyst": {"operate", "observe"},
    "observer": {"observe"},
    "approver": {"approve", "observe"},
    "auditor": {"audit", "observe"},
}


@dataclass
class OperatorIdentity:
    username: str
    role: str
    session_id: str
    mission_id: str


class AuthService:
    """Minimal HS256 JWT implementation using only the standard library."""

    def __init__(self, secret: str, users: dict[str, dict[str, str]] | None = None):
        self.secret = secret.encode("utf-8")
        self.users = users or {}

    def authenticate(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        return bool(user and user.get("password") == password)

    def issue_token(self, identity: OperatorIdentity, lifetime_seconds: int = 3600) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": identity.username,
            "role": identity.role,
            "sid": identity.session_id,
            "mid": identity.mission_id,
            "exp": int(time.time()) + lifetime_seconds,
        }
        return ".".join([
            self._b64(header),
            self._b64(payload),
            self._sign(header, payload),
        ])

    def verify_token(self, token: str) -> OperatorIdentity:
        header_b64, payload_b64, signature = token.split(".", 2)
        header = json.loads(base64.urlsafe_b64decode(self._pad(header_b64)).decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(self._pad(payload_b64)).decode("utf-8"))
        expected = self._sign(header, payload)
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid token signature")
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("token expired")
        return OperatorIdentity(
            username=str(payload["sub"]),
            role=str(payload["role"]),
            session_id=str(payload["sid"]),
            mission_id=str(payload["mid"]),
        )

    def has_permission(self, role: str, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(role, set())

    def require_role(self, role: str, *allowed_roles: str):
        if role not in allowed_roles:
            raise PermissionError(f"role {role} is not permitted")

    def _b64(self, obj: dict) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def _sign(self, header: dict, payload: dict) -> str:
        signing_input = f"{self._b64(header)}.{self._b64(payload)}".encode("utf-8")
        return base64.urlsafe_b64encode(hmac.new(self.secret, signing_input, hashlib.sha256).digest()).decode("utf-8").rstrip("=")

    def _pad(self, value: str) -> str:
        return value + "=" * (-len(value) % 4)

