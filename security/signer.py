"""Payload signing helpers for commands, workers, and artifacts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict


class CommandSigner:
    """HMAC signer used across worker dispatch, approvals, and artifact integrity checks."""

    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def sign(self, payload: Dict[str, Any]) -> Dict[str, str]:
        encoded = self._canonical(payload)
        signature = hmac.new(self.secret, encoded, hashlib.sha256).digest()
        return {
            "ts": str(int(time.time())),
            "signature": base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("="),
        }

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        expected = self.sign(payload)["signature"]
        return hmac.compare_digest(expected, signature)

    def fingerprint(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _canonical(self, payload: Dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

