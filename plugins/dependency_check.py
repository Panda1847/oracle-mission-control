"""Dependency and health checks for enterprise plugins."""

from __future__ import annotations

import shutil
from typing import Dict, List


def missing_binaries(required_binaries: list[str]) -> List[str]:
    return [binary for binary in required_binaries if binary and shutil.which(binary) is None]


def health_status(required_binaries: list[str]) -> Dict[str, object]:
    missing = missing_binaries(required_binaries)
    return {
        "healthy": len(missing) == 0,
        "missing_binaries": missing,
    }

