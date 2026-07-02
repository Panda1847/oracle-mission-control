"""Enterprise message bus with in-memory fallback and queue semantics."""

from __future__ import annotations

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import os
import logging
from threading import RLock
import time
from typing import Any, Callable, Deque, Dict, List, Optional
from uuid import uuid4

from .deadletter import DeadLetterQueue
from .event_stream import EventMessage, EventStream
from telemetry.metrics import GLOBAL_METRICS

log = logging.getLogger("oracle.queue")


class RedisQueueBus:
    """
    Queue abstraction that keeps ORACLE decoupled even when Redis is unavailable.

    The interface is Redis/Rabbit-friendly, but the default implementation remains
    in-process and testable.
    """

    def __init__(self, redis_url: str = "", *, stream: Optional[EventStream] = None, deadletter: Optional[DeadLetterQueue] = None):
        self.redis_url = redis_url
        self.stream = stream or EventStream()
        self.deadletter = deadletter or DeadLetterQueue()
        self._client = None
        self._queues: Dict[str, Deque[EventMessage]] = defaultdict(deque)
        self._subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = defaultdict(list)
        self._diagnostics: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._lock = RLock()
        self.metrics = GLOBAL_METRICS
        self._subscriber_warn_s = float(os.environ.get("ORACLE_EVENTBUS_SUBSCRIBER_WARN_S", "1.0") or 1.0)
        self._subscriber_pool = ThreadPoolExecutor(
            max_workers=max(1, int(os.environ.get("ORACLE_EVENTBUS_SUBSCRIBER_WORKERS", "4") or 4)),
            thread_name_prefix="oracle-bus",
        )
        self._init_redis_client()

    def publish(self, topic: str, payload: Dict[str, Any], trace_id: str = "") -> Dict[str, Any]:
        message = self.stream.publish(topic, payload, trace_id or uuid4().hex)
        with self._lock:
            self._queues[topic].append(message)
            subscribers = list(self._subscribers.get(topic, []))
        message_dict = message.to_dict()
        for callback in subscribers:
            self._subscriber_pool.submit(self._safe_call, callback, message_dict, topic, payload)
        return message_dict

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        with self._lock:
            self._subscribers[topic].append(callback)

    def enqueue_job(self, topic: str, payload: Dict[str, Any], trace_id: str = "") -> Dict[str, Any]:
        return self.publish(topic, payload, trace_id=trace_id)

    def consume_once(self, topic: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self._queues.get(topic):
                return None
            message = self._queues[topic].popleft()
        return message.to_dict()

    def pending_jobs(self, topic: Optional[str] = None) -> int:
        with self._lock:
            if topic:
                return len(self._queues.get(topic, []))
            return sum(len(queue) for queue in self._queues.values())

    def timeline(self, topic: Optional[str] = None, limit: int = 200):
        return self.stream.timeline(topic=topic, limit=limit)

    def diagnostics(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._diagnostics)
        return items[-limit:]

    def close(self):
        self._subscriber_pool.shutdown(wait=False, cancel_futures=True)
        if self._client is not None and hasattr(self._client, "close"):
            try:
                self._client.close()
            except Exception:
                pass

    def _record_diagnostic(self, item: Dict[str, Any]):
        with self._lock:
            self._diagnostics.append(dict(item))

    def _init_redis_client(self):
        redis_url = str(self.redis_url or os.environ.get("ORACLE_REDIS_URL", "") or "").strip()
        if not redis_url:
            return
        try:
            import redis  # type: ignore
            client = redis.Redis.from_url(redis_url)
            client.ping()
            self._client = client
        except Exception as exc:
            log.warning("Redis unavailable - running in-process queue mode: %s", exc)
            self._client = None

    def _safe_call(
        self,
        callback: Callable[[Dict[str, Any]], None],
        message: Dict[str, Any],
        topic: str,
        payload: Dict[str, Any],
    ):
        started = time.time()
        callback_name = getattr(callback, "__name__", callback.__class__.__name__)
        diagnostic = {
            "topic": topic,
            "callback": callback_name,
            "status": "ok",
            "elapsed_s": 0.0,
        }
        try:
            callback(dict(message))
            self.metrics.inc("eventbus_subscriber_success_total", labels={"topic": topic})
        except Exception as exc:
            self.deadletter.add(topic, payload, f"subscriber error: {exc}")
            self.metrics.inc("eventbus_subscriber_failure_total", labels={"topic": topic})
            diagnostic["status"] = "error"
            diagnostic["reason"] = str(exc)
        finally:
            elapsed = max(0.0, time.time() - started)
            diagnostic["elapsed_s"] = round(elapsed, 6)
            self.metrics.observe("eventbus_subscriber_duration_seconds", elapsed, labels={"topic": topic})
            if diagnostic["status"] == "ok" and elapsed >= self._subscriber_warn_s:
                self.metrics.inc("eventbus_subscriber_slow_total", labels={"topic": topic})
                diagnostic["status"] = "slow"
                diagnostic["reason"] = f"elapsed {elapsed:.3f}s exceeded warning threshold {self._subscriber_warn_s:.3f}s"
            self._record_diagnostic(diagnostic)
