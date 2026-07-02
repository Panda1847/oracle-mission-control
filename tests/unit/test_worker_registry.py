import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from workers.registration import WorkerRegistry


def test_worker_registry_tracks_health_and_selection():
    registry = WorkerRegistry(heartbeat_timeout_seconds=60)
    registry.register("local-node", "local://executor", ["*"], transport="local", role="local")
    registry.register("remote-a", "http://127.0.0.1:9999", ["nmap"], transport="http", role="remote")

    registry.acknowledge("remote-a")
    registry.complete("remote-a", True)

    best = registry.healthiest("nmap")

    assert best is not None
    assert best.worker_id == "remote-a"
    assert best.health_score > 0
