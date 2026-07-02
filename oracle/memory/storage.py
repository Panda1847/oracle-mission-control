"""
ORACLE — Storage  (memory/storage.py)
JSON-file persistence for mission intelligence.
"""
from __future__ import annotations
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("oracle.storage")


class Storage:
    """Simple JSON key-value persistence backed by a directory."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
        return self.base_dir / f"{safe}.json"

    def save(self, key: str, data: Dict[str, Any]) -> bool:
        try:
            target = self._path(key)
            tmp = target.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(target)
            return True
        except Exception as e:
            log.error("Storage save error [%s]: %s", key, e)
            return False

    def load(self, key: str) -> Optional[Dict[str, Any]]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except Exception as e:
            log.error("Storage load error [%s]: %s", key, e)
            return None

    def delete(self, key: str) -> bool:
        p = self._path(key)
        if p.exists():
            p.unlink()
            return True
        return False

    def list_keys(self) -> list:
        return [p.stem for p in self.base_dir.glob("*.json")]

    def export_json(self, key: str) -> str:
        """Return raw JSON string for a stored mission."""
        p = self._path(key)
        return p.read_text() if p.exists() else "{}"

    def backup(self, key: str, tag: str = "") -> Optional[Path]:
        """
        Create a best-effort .bak snapshot of the mission JSON.
        Returns the backup path, or None if the source doesn't exist.
        """
        src = self._path(key)
        if not src.exists():
            return None
        ts = time.strftime("%Y%m%d-%H%M%S")
        suffix = f".{tag}" if tag else ""
        dst = src.with_suffix(f".bak.{ts}{suffix}.json")
        try:
            shutil.copy2(src, dst)
            return dst
        except Exception as e:
            log.error("Storage backup error [%s]: %s", key, e)
            return None

    def list_backups(self, key: str) -> list[Path]:
        src = self._path(key)
        base = src.name.replace(".json", ".bak.")
        return sorted(self.base_dir.glob(base + "*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    def restore_backup(self, key: str, which: str = "last") -> Optional[Path]:
        """
        Restore from backup. `which` supports: "last" or an exact backup filename.
        Returns restored backup path used, or None if not found.
        """
        src = self._path(key)
        backups = self.list_backups(key)
        if which == "last":
            if not backups:
                return None
            chosen = backups[0]
        else:
            chosen = None
            for b in backups:
                if b.name == which or str(b) == which:
                    chosen = b
                    break
            if chosen is None:
                return None
        try:
            shutil.copy2(chosen, src)
            return chosen
        except Exception as e:
            log.error("Storage restore error [%s]: %s", key, e)
            return None
