import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from queuebus.event_stream import EventStream as RootEventStream
from queuebus.redis_bus import RedisQueueBus as RootRedisQueueBus

from oracle.queue.event_stream import EventStream as OracleEventStream
from oracle.queue.redis_bus import RedisQueueBus as OracleRedisQueueBus


def test_root_queue_compat_reexports_authoritative_classes():
    assert RootRedisQueueBus is OracleRedisQueueBus
    assert RootEventStream is OracleEventStream


def test_root_queue_bus_compat_exposes_diagnostics():
    bus = RootRedisQueueBus()
    bus.publish("compat.event", {"value": 1}, trace_id="compat")
    assert hasattr(bus, "diagnostics")
    assert isinstance(bus.diagnostics(), list)
    bus.close()
