"""Tracks action outcomes for retries, fallback, and checkpoints."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
from threading import RLock
from typing import Dict

from oracle.core.models import Action, ActionResult


@dataclass
class JobRecord:
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    blocked: int = 0
    last_error: str = ""
    last_returncode: int = 0


class JobTracker:
    """Maintains execution history keyed by deterministic action signature."""

    def __init__(self, state_path: str | Path | None = None):
        self._records: Dict[str, JobRecord] = defaultdict(JobRecord)
        self._lock = RLock()
        self._state_path = Path(state_path) if state_path else None
        if self._state_path is not None:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    @staticmethod
    def signature(action: Action) -> str:
        args = tuple(sorted((action.args or {}).items()))
        return f"{action.phase}|{action.tool}|{action.target}|{args}"

    def record_result(self, result: ActionResult):
        with self._lock:
            record = self._records[self.signature(result.action)]
            record.attempts += 1
            record.last_returncode = result.returncode
            if result.success:
                record.successes += 1
                record.last_error = ""
            else:
                record.failures += 1
                record.last_error = result.stderr[:500]
            self._save()

    def record_block(self, action: Action, reason: str):
        with self._lock:
            record = self._records[self.signature(action)]
            record.attempts += 1
            record.blocked += 1
            record.failures += 1
            record.last_error = reason[:500]
            self._save()

    def record_error(self, action: Action, reason: str):
        with self._lock:
            record = self._records[self.signature(action)]
            record.attempts += 1
            record.failures += 1
            record.last_error = reason[:500]
            self._save()

    def stats_for(self, action: Action) -> JobRecord:
        with self._lock:
            return self._records[self.signature(action)]

    def has_success(self, action: Action) -> bool:
        return self.stats_for(action).successes > 0

    def count_success(self, tool: str | None = None, phase: str | None = None) -> int:
        total = 0
        with self._lock:
            for signature, record in self._records.items():
                if record.successes == 0:
                    continue
                parts = signature.split("|", 3)
                sig_phase = parts[0]
                sig_tool = parts[1]
                if tool and sig_tool != tool:
                    continue
                if phase and sig_phase != phase:
                    continue
                total += record.successes
        return total

    def _load(self):
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        for signature, payload in raw.items():
            if not isinstance(payload, dict):
                continue
            record = JobRecord(
                attempts=int(payload.get("attempts", 0) or 0),
                successes=int(payload.get("successes", 0) or 0),
                failures=int(payload.get("failures", 0) or 0),
                blocked=int(payload.get("blocked", 0) or 0),
                last_error=str(payload.get("last_error", "")),
                last_returncode=int(payload.get("last_returncode", 0) or 0),
            )
            self._records[signature] = record

    def _save(self):
        if self._state_path is None:
            return
        payload = {
            signature: {
                "attempts": record.attempts,
                "successes": record.successes,
                "failures": record.failures,
                "blocked": record.blocked,
                "last_error": record.last_error,
                "last_returncode": record.last_returncode,
            }
            for signature, record in self._records.items()
        }
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        tmp_path.replace(self._state_path)
