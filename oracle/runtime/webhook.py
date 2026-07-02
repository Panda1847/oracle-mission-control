from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    timeout_s: float = 3.0
    queue_max: int = 128


class WebhookNotifier:
    """
    Non-blocking webhook sender (background queue).
    Drops on overload or on any error; never raises into mission loop.
    """

    def __init__(self, cfg: WebhookConfig):
        self.cfg = cfg
        self._q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=max(1, int(cfg.queue_max)))
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._worker, daemon=True, name="oracle-webhook")
        self._t.start()

    def notify(self, event: str, payload: Dict[str, Any]) -> bool:
        if not self.cfg.url:
            return False
        msg = {"ts": _utc_ts(), "event": event, "payload": payload}
        try:
            self._q.put_nowait(msg)
            return True
        except queue.Full:
            return False

    def close(self):
        self._stop.set()
        self._t.join(timeout=1.0)

    def _worker(self):
        while not self._stop.is_set():
            try:
                msg = self._q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                requests.post(self.cfg.url, json=msg, timeout=float(self.cfg.timeout_s))
            except Exception:
                pass
            finally:
                try:
                    self._q.task_done()
                except Exception:
                    pass

