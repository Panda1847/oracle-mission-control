"""Lightweight worker request signing."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Dict


class WorkerAuth:
    """Shared-secret request signing for worker/master traffic."""

    WEAK_DEFAULTS = {
        "",
        "oracle-worker-secret",
        "change-me",
        "change-this-worker-secret",
        "changeme",
        "default",
    }
    MIN_SECRET_LEN = 16

    def __init__(self, shared_secret: str | None = None, *, allow_insecure: bool | None = None):
        value = self.resolve_shared_secret(shared_secret, allow_insecure=allow_insecure)
        self.shared_secret = value.encode("utf-8")

    @classmethod
    def resolve_shared_secret(cls, shared_secret: str | None = None, *, allow_insecure: bool | None = None) -> str:
        raw = str(
            shared_secret
            or os.environ.get("ORACLE_WORKER_SECRET")
            or os.environ.get("ORACLE_WORKER_SHARED_SECRET")
            or os.environ.get("WORKER_SHARED_SECRET")
            or ""
        ).strip()
        insecure = (
            allow_insecure
            if allow_insecure is not None
            else str(os.environ.get("ORACLE_ALLOW_INSECURE_WORKER_SECRET", "")).strip().lower() in {"1", "true", "yes", "on"}
        )
        if (not raw or raw.lower() in cls.WEAK_DEFAULTS or len(raw) < cls.MIN_SECRET_LEN) and not insecure:
            reason = "blank"
            if raw.lower() in cls.WEAK_DEFAULTS:
                reason = "weak-default"
            elif raw and len(raw) < cls.MIN_SECRET_LEN:
                reason = "too-short"
            raise ValueError(
                f"workers.shared_secret rejected ({reason}). "
                f"Provide a strong secret (>= {cls.MIN_SECRET_LEN} chars), or explicitly set "
                "ORACLE_ALLOW_INSECURE_WORKER_SECRET=1 for insecure dev mode."
            )
        return raw

    def sign(self, payload: dict, timestamp: str | None = None) -> Dict[str, str]:
        stamp = timestamp or str(int(time.time()))
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        msg = stamp.encode("utf-8") + b"." + body
        signature = hmac.new(self.shared_secret, msg, hashlib.sha256).hexdigest()
        return {
            "X-Oracle-Timestamp": stamp,
            "X-Oracle-Signature": signature,
        }

    def verify(self, payload: dict, headers: dict) -> bool:
        stamp = str(headers.get("X-Oracle-Timestamp", ""))
        signature = str(headers.get("X-Oracle-Signature", ""))
        expected = self.sign(payload, timestamp=stamp)["X-Oracle-Signature"]
        return bool(signature) and hmac.compare_digest(signature, expected)
