"""ORACLE package."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

__version__ = "3.2.0"
__schema_version__ = "oracle-delivery.v1"


def _detect_git_hash() -> str:
    env_hash = str(os.environ.get("ORACLE_BUILD_GIT", "") or "").strip()
    if env_hash:
        return env_hash
    try:
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=1.5,
            check=True,
        )
        return proc.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


__build_git__ = _detect_git_hash()


def get_build_identity() -> dict[str, Any]:
    return {
        "semantic_version": __version__,
        "git_hash": __build_git__,
        "schema_version": __schema_version__,
    }


__all__ = ["__version__", "__schema_version__", "__build_git__", "get_build_identity"]
