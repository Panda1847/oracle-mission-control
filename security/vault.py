"""Encrypted local secrets vault backed by Fernet."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretVault:
    """Small encrypted vault for operator/API secrets."""

    def __init__(self, path: str | Path, passphrase: str):
        self.path = Path(path)
        self.passphrase = passphrase.encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def store(self, key: str, value: str):
        data = self._load()
        data[key] = value
        self._write(data)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._load().get(key, default)

    def delete(self, key: str):
        data = self._load()
        data.pop(key, None)
        self._write(data)

    def export_masked(self) -> Dict[str, str]:
        return {key: "***" for key in self._load().keys()}

    def _load(self) -> Dict[str, str]:
        if not self.path.exists():
            return {}
        blob = json.loads(self.path.read_text(encoding="utf-8"))
        salt = base64.urlsafe_b64decode(blob["salt"].encode("utf-8"))
        token = blob["token"].encode("utf-8")
        fernet = Fernet(self._derive_key(salt))
        return json.loads(fernet.decrypt(token).decode("utf-8"))

    def _write(self, payload: Dict[str, str]):
        salt = os.urandom(16)
        fernet = Fernet(self._derive_key(salt))
        token = fernet.encrypt(json.dumps(payload, sort_keys=True).encode("utf-8")).decode("utf-8")
        self.path.write_text(
            json.dumps(
                {
                    "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
                    "token": token,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.path.chmod(0o600)

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
        return base64.urlsafe_b64encode(kdf.derive(self.passphrase))

