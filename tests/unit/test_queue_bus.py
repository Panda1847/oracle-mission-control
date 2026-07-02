from oracle.queue.redis_bus import RedisQueueBus
import os
import time


def test_queue_bus_publish_consume_and_deadletter():
    bus = RedisQueueBus()
    called = []

    def subscriber(message):
        called.append(message["payload"]["value"])

    bus.subscribe("mission.event", subscriber)
    bus.publish("mission.event", {"value": 7}, trace_id="t1")
    consumed = bus.consume_once("mission.event")
    deadline = time.time() + 1.0
    while time.time() < deadline and called != [7]:
        time.sleep(0.01)

    assert consumed["payload"]["value"] == 7
    assert called == [7]
    assert bus.timeline(limit=1)[0]["topic"] == "mission.event"
    bus.close()


def test_queue_bus_isolates_subscriber_failures():
    bus = RedisQueueBus()
    called = []

    def bad_subscriber(_message):
        raise RuntimeError("boom")

    def good_subscriber(message):
        called.append(message["payload"]["value"])

    bus.subscribe("mission.event", bad_subscriber)
    bus.subscribe("mission.event", good_subscriber)
    bus.publish("mission.event", {"value": 9}, trace_id="t2")

    deadline = time.time() + 1.0
    while time.time() < deadline and called != [9]:
        time.sleep(0.01)

    dead = bus.deadletter.items()
    assert called == [9]
    assert any("subscriber error" in item["reason"] for item in dead)
    assert any(item["status"] == "error" for item in bus.diagnostics())
    bus.close()


def test_queue_bus_publish_is_non_blocking_for_slow_subscribers():
    prior_warn = os.environ.get("ORACLE_EVENTBUS_SUBSCRIBER_WARN_S")
    os.environ["ORACLE_EVENTBUS_SUBSCRIBER_WARN_S"] = "0.01"
    bus = RedisQueueBus()
    called = []

    def slow_subscriber(message):
        time.sleep(0.05)
        called.append(message["payload"]["value"])

    bus.subscribe("mission.event", slow_subscriber)

    started = time.time()
    bus.publish("mission.event", {"value": 11}, trace_id="t3")
    publish_elapsed = time.time() - started

    deadline = time.time() + 1.0
    while time.time() < deadline and called != [11]:
        time.sleep(0.01)

    diagnostics = bus.diagnostics()
    assert publish_elapsed < 0.03
    assert called == [11]
    assert any(item["status"] == "slow" for item in diagnostics)
    bus.close()
    if prior_warn is None:
        os.environ.pop("ORACLE_EVENTBUS_SUBSCRIBER_WARN_S", None)
    else:
        os.environ["ORACLE_EVENTBUS_SUBSCRIBER_WARN_S"] = prior_warn


def test_queue_bus_failure_and_slow_callback_are_recorded_separately():
    prior_warn = os.environ.get("ORACLE_EVENTBUS_SUBSCRIBER_WARN_S")
    os.environ["ORACLE_EVENTBUS_SUBSCRIBER_WARN_S"] = "0.01"
    bus = RedisQueueBus()

    def bad_subscriber(_message):
        time.sleep(0.02)
        raise RuntimeError("boom-2")

    bus.subscribe("mission.event", bad_subscriber)
    bus.publish("mission.event", {"value": 13}, trace_id="t4")

    deadline = time.time() + 1.0
    while time.time() < deadline:
        diagnostics = bus.diagnostics()
        if diagnostics:
            break
        time.sleep(0.01)

    diagnostics = bus.diagnostics()
    assert any(item["status"] == "error" for item in diagnostics)
    assert not any(item["status"] == "slow" and item.get("callback") == "bad_subscriber" for item in diagnostics)
    bus.close()
    if prior_warn is None:
        os.environ.pop("ORACLE_EVENTBUS_SUBSCRIBER_WARN_S", None)
    else:
        os.environ["ORACLE_EVENTBUS_SUBSCRIBER_WARN_S"] = prior_warn
