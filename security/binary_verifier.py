"""Binary checksum verification helpers."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Dict, Iterable


def sha256_file(path: str | Path) -> str:
    handle = Path(path).open("rb")
    try:
        digest = hashlib.sha256()
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        handle.close()


def verify_binaries(required_binaries: Iterable[str], checksums: Dict[str, str] | None = None) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    checksums = dict(checksums or {})
    for binary in required_binaries:
        binary_path = shutil.which(binary)
        if not binary_path:
            results[binary] = {"present": False, "verified": False, "path": ""}
            continue
        checksum = sha256_file(binary_path)
        expected = checksums.get(binary, "")
        results[binary] = {
            "present": True,
            "verified": (not expected) or (expected == checksum),
            "path": binary_path,
            "sha256": checksum,
        }
    return results

