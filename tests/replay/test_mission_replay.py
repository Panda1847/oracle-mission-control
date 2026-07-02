import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.orchestrator.event_bus import EventBus
from memory.replay import ReplayStore
from storage.snapshots import SnapshotStore


def test_event_bus_timeline_replay_and_snapshot(tmp_path):
    bus = EventBus()
    bus.publish("start", {"mission": "r1"}, trace_id="trace-replay")
    bus.publish("decision", {"tool": "nmap"}, trace_id="trace-replay")
    bus.publish("complete", {"status": "complete"}, trace_id="trace-replay")

    store = SnapshotStore(tmp_path / "replay")
    snapshot = {"timeline": bus.timeline(limit=10)}
    path = store.create("replay-mission", snapshot, tag="timeline")

    assert path.exists()
    assert len(snapshot["timeline"]) == 3
    assert snapshot["timeline"][1]["topic"] == "decision"


def test_replay_store_persists_and_loads_iteration_artifacts(tmp_path):
    store = ReplayStore(tmp_path / "replay-artifacts")
    artifact = {
        "mission": "m1",
        "branch": "normal",
        "planner_extra": {"phase": "DISCOVERY"},
        "graph_snapshot_before": {"hosts": {}},
        "graph_snapshot_after": {"hosts": {"10.0.0.1": {}}},
        "raw_ai_response": {"tool": "nmap"},
    }

    path = store.create("m1", artifact, branch="normal")
    loaded = store.load(path)

    assert path.exists()
    assert loaded["mission"] == "m1"
    assert loaded["branch"] == "normal"
    assert loaded["graph_snapshot_after"]["hosts"]["10.0.0.1"] == {}
