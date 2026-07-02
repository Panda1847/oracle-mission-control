"""Compatibility export for the authoritative enterprise dead-letter queue."""

from oracle.queue.deadletter import DeadLetterQueue, DeadLetterRecord

__all__ = ["DeadLetterQueue", "DeadLetterRecord"]
