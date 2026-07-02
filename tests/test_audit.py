import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from oracle.runtime.audit import AuditLogger, AuditConfig


def test_audit_logger_writes_jsonl(tmp_path):
    p = tmp_path / "a.jsonl"
    a = AuditLogger(AuditConfig(path=p))
    a.log("x", {"k": "v"})
    lines = p.read_text().splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["event"] == "x"
    assert "hash" in obj

