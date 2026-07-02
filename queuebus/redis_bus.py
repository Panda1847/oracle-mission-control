"""Compatibility export for the authoritative enterprise queue bus."""

from oracle.queue.redis_bus import RedisQueueBus

__all__ = ["RedisQueueBus"]
