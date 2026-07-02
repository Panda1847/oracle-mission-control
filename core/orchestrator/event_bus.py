"""Enterprise event bus with replay and queue-backed delivery."""

from __future__ import annotations

from typing import Callable

from oracle.queue.deadletter import DeadLetterQueue
from oracle.queue.event_stream import EventStream
from oracle.queue.redis_bus import RedisQueueBus
from telemetry.metrics import GLOBAL_METRICS
from telemetry.tracing import GLOBAL_TRACES


class EventBus:
    """Publish/subscribe bus with event timeline support."""

    def __init__(self, *, stream: EventStream | None = None, queue_bus: RedisQueueBus | None = None):
        self.stream = stream or EventStream()
        self.deadletter = DeadLetterQueue()
        self.queue = queue_bus or RedisQueueBus(stream=self.stream, deadletter=self.deadletter)
        self.metrics = GLOBAL_METRICS
        self.tracer = GLOBAL_TRACES

    def subscribe(self, event: str, callback: Callable):
        self.queue.subscribe(event, lambda message: callback(message.get("payload", {})))

    def publish(self, event: str, payload, trace_id: str = ""):
        message = self.queue.publish(event, payload, trace_id=trace_id or self.tracer.new_trace_id(event))
        self.metrics.inc("mission_events_total", labels={"topic": event})
        self.tracer.record_event(message["trace_id"], event, dict(payload or {}))
        return message

    def timeline(self, event: str | None = None, limit: int = 200):
        return self.queue.timeline(topic=event, limit=limit)

    def close(self):
        if hasattr(self.queue, "close"):
            self.queue.close()
