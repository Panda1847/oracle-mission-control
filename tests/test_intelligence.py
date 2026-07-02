import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from oracle.core.intelligence import IntelligenceEngine


def test_offline_enrichment_apache_2449():
    eng = IntelligenceEngine(online_enabled=False)
    info = eng.enrich_offline(version="Apache httpd 2.4.49")
    assert "CVE-2021-41773" in info.get("cves", [])


def test_online_queue_non_blocking_and_updates_callback():
    updated = []
    ev = threading.Event()

    def cb(update: dict):
        updated.append(update)
        ev.set()

    eng = IntelligenceEngine(online_enabled=True, update_cb=cb, queue_max=1)

    # Monkeypatch the online lookup to avoid real network calls.
    eng._online_lookup = lambda version: {"cves": ["CVE-2099-0001"], "cvss": 9.9, "sources": ["nvd"]}

    eng.enqueue_online(version="Apache httpd 2.4.49", host="10.0.0.5", port=80, protocol="tcp")
    assert ev.wait(1.0), "expected callback from background worker"
    assert updated[0]["host"] == "10.0.0.5"
    assert "CVE-2099-0001" in updated[0]["cves"]

    eng.close()


def test_online_queue_drops_when_full():
    eng = IntelligenceEngine(online_enabled=True, queue_max=1)

    # Force the worker to be slow so the queue fills.
    def slow_lookup(version: str):
        time.sleep(0.2)
        return {"cves": ["CVE-2099-0002"], "sources": ["nvd"]}

    eng._online_lookup = slow_lookup

    # First one occupies queue/worker, second should drop without blocking/raising.
    eng.enqueue_online(version="A", host="h", port=1, protocol="tcp")
    eng.enqueue_online(version="B", host="h", port=2, protocol="tcp")

    eng.close()

