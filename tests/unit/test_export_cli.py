import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from export.package import build_mission_export
from oracle import get_build_identity
from oracle.cli.export import run as run_export
from oracle.memory.storage import Storage


def test_build_identity_contains_required_fields():
    identity = get_build_identity()
    assert identity["semantic_version"]
    assert identity["git_hash"]
    assert identity["schema_version"]


def test_export_cli_writes_structured_mission_exports(tmp_path):
    storage = Storage(tmp_path / "missions")
    storage.save(
        "mission-a",
        {
            "phase": "REPORTING",
            "status": "complete",
            "hosts": {"10.0.0.5": {"ip": "10.0.0.5", "hostname": "", "os_guess": "Linux", "ports": []}},
            "findings": [{"title": "Test finding", "host": "10.0.0.5", "port": 80, "severity": "HIGH", "plugin": "http"}],
            "evidence": [{"entity": "host", "value": "10.0.0.5", "confidence": 0.9}],
            "topology": {"nodes": [{"kind": "host", "label": "10.0.0.5"}], "edges": []},
            "stats": {"hosts": 1, "findings": 1, "critical": 0, "high": 1},
        },
    )
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "mission-a_audit.jsonl").write_text('{"event":"mission_start","payload":{"ok":true}}\n', encoding="utf-8")

    rc = run_export(["--mission", "mission-a"], data_dir=tmp_path / "missions", log_dir=log_dir)

    export_dir = tmp_path / "missions" / "exports" / "mission-a"
    assert rc == 0
    assert (export_dir / "executive_summary.md").exists()
    assert (export_dir / "findings.json").exists()
    assert (export_dir / "evidence.jsonl").exists()
    assert (export_dir / "provenance.jsonl").exists()
    assert (export_dir / "topology.json").exists()
    assert (export_dir / "replay.jsonl").exists()
    assert (export_dir / "council_rounds.json").exists()
    assert (export_dir / "council_review.json").exists()
    assert (export_dir / "remediation.md").exists()
    assert (export_dir / "package.zip").exists()
    archive = zipfile.ZipFile(export_dir / "package.zip")
    names = set(archive.namelist())
    assert "exports/executive_summary.md" in names
    assert "exports/findings.json" in names
    assert "exports/evidence.jsonl" in names
    assert "exports/provenance.jsonl" in names
    assert "exports/topology.json" in names
    assert "exports/replay.jsonl" in names
    assert "exports/council_rounds.json" in names
    assert "exports/council_review.json" in names
    assert "exports/remediation.md" in names


def test_export_cli_fails_for_missing_mission(tmp_path):
    rc = run_export(["--mission", "missing"], data_dir=tmp_path / "missions", log_dir=tmp_path / "logs")
    assert rc == 1
