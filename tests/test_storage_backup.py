import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from oracle.memory.storage import Storage


def test_storage_backup_and_restore(tmp_path):
    s = Storage(tmp_path)
    key = "m"
    s.save(key, {"a": 1})
    b = s.backup(key, tag="x")
    assert b is not None and b.exists()

    s.save(key, {"a": 2})
    restored = s.restore_backup(key, which="last")
    assert restored is not None
    data = s.load(key)
    assert data["a"] == 1

