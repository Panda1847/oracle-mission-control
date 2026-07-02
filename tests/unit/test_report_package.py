import io
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from export.package import build_mission_package
from memory.replay import ReplayStore


def test_build_mission_package_contains_canonical_artifacts(tmp_path):
    replay_store = ReplayStore(tmp_path / "replay")
    replay_path = replay_store.create(
        "pkg-mission",
        {
            "replay_id": "abc123",
            "mission": "pkg-mission",
            "phase": "REPORTING",
            "graph_snapshot_after": {"hosts": {"10.0.0.5": {}}, "findings": [{"fid": "f1"}]},
        },
        branch="normal",
    )
    package = build_mission_package(
        "pkg-mission",
        mission_snapshot={"phase": "COMPLETE", "status": "complete"},
        graph_snapshot={"hosts": {"10.0.0.5": {}}, "findings": [{"fid": "f1"}]},
        summary={"mission": "pkg-mission"},
        evidence={"count": 1, "evidence_records": [{"entity": "host", "value": "10.0.0.5"}]},
        intelligence_report={
            "report_schema_version": "v1",
            "machine_package": {"mission": "pkg-mission"},
            "executive_summary": "Mission summary",
            "ranked_findings": [{"title": "HTTP exposed", "host": "10.0.0.5", "port": 80, "severity": "HIGH"}],
            "remediation_text": ["Patch Apache"],
        },
        bundle={"mission": "pkg-mission"},
        pdf_report=b"%PDF-1.4\n%",
        replay_artifacts=[replay_path],
        provenance_records=[{"event": "mission_start", "payload": {"mission": "pkg-mission"}}],
    )

    archive = zipfile.ZipFile(io.BytesIO(package.payload))
    names = sorted(archive.namelist())
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    intelligence = json.loads(archive.read("reports/intelligence.json").decode("utf-8"))

    assert "mission/snapshot.json" in names
    assert "reports/summary.json" in names
    assert "reports/evidence.json" in names
    assert "reports/intelligence.json" in names
    assert "reports/bundle.json" in names
    assert "reports/summary.pdf" in names
    assert f"replay/{replay_path.name}" in names
    assert "exports/executive_summary.md" in names
    assert "exports/findings.json" in names
    assert "exports/evidence.jsonl" in names
    assert "exports/provenance.jsonl" in names
    assert "exports/topology.json" in names
    assert "exports/replay.jsonl" in names
    assert "exports/council_rounds.json" in names
    assert "exports/council_review.json" in names
    assert "exports/remediation.md" in names
    assert "exports/summary.pdf" in names
    assert manifest["mission"] == "pkg-mission"
    assert manifest["counts"]["replay_artifacts"] == 1
    assert manifest["counts"]["council_rounds"] == 0
    assert manifest["counts"]["delivery_exports"] >= 7
    assert intelligence["machine_package"]["mission"] == "pkg-mission"
