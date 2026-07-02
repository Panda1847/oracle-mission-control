import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from storage.db import Database


def test_database_thread_safe_writes(tmp_path):
    db = Database(tmp_path / "meta.sqlite")
    mission_id = "m-threaded"

    def worker(idx: int):
        db.upsert_mission(mission_id, status="running", phase=f"P{idx}", payload_json='{"ok":true}')
        for n in range(25):
            db.add_artifact(mission_id, "report", f"/tmp/{idx}-{n}.json", "application/json")

    threads = [threading.Thread(target=worker, args=(idx,)) for idx in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    artifacts = db.artifacts_for(mission_id)
    assert len(artifacts) == 8 * 25
