"""Enterprise message-bus package (mission event queue, dead-letter queue, Redis-shaped bus).

Note: this package used to be named `queue`, which shadowed Python's stdlib
`queue` module for any process that added the repo root to sys.path. That
caused an intermittent circular import in anything that pulled in
`concurrent.futures` (which itself does `import queue` internally) before
this package had finished initializing. Renaming it to `queuebus` removes
the collision entirely -- no more path-loading tricks required to get at
the real standard library module.
"""

from __future__ import annotations

from queue import Empty, Full, LifoQueue, PriorityQueue, Queue, SimpleQueue

from .deadletter import DeadLetterQueue, DeadLetterRecord
from .event_stream import EventMessage, EventStream
from .redis_bus import RedisQueueBus

__all__ = [
    "Queue",
    "LifoQueue",
    "PriorityQueue",
    "SimpleQueue",
    "Empty",
    "Full",
    "DeadLetterQueue",
    "DeadLetterRecord",
    "EventMessage",
    "EventStream",
    "RedisQueueBus",
]
