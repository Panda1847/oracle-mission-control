"""Background queue consumer utilities."""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .redis_bus import RedisQueueBus


class JobConsumer:
    """Consumes queue messages in a background thread without blocking the mission loop."""

    def __init__(
        self,
        bus: RedisQueueBus,
        topic: str,
        handler: Callable[[dict], None],
        *,
        poll_interval: float = 0.1,
        on_error: Optional[Callable[[dict, Exception], None]] = None,
    ):
        self.bus = bus
        self.topic = topic
        self.handler = handler
        self.poll_interval = poll_interval
        self.on_error = on_error
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            message = self.bus.consume_once(self.topic)
            if message is None:
                time.sleep(self.poll_interval)
                continue
            try:
                self.handler(message)
            except Exception as exc:
                self.bus.deadletter.add(self.topic, message, f"consumer error: {exc}")
                if self.on_error:
                    self.on_error(message, exc)

