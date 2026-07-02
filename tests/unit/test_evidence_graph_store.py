import sys
from pathlib import Path
import sqlite3

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from memory.graph_store import EvidenceGraphStore


def test_evidence_graph_store_deduplicates_and_links(tmp_path):
    store = EvidenceGraphStore(tmp_path / "intel.sqlite", mission_id="m1")
    record1 = store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"state": "open", "version": "Apache 2.4.41"},
        related_entities=["10.0.0.5"],
    )
    record2 = store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"state": "open", "version": "Apache 2.4.41"},
        related_entities=["10.0.0.5"],
    )

    active = store.active_evidence()

    assert record1.record_id == record2.record_id
    assert len(active) == 1
    assert store.related(record1.record_id)


def test_evidence_graph_store_detects_contradictions(tmp_path):
    store = EvidenceGraphStore(tmp_path / "intel.sqlite", mission_id="m1")
    store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"state": "open", "version": "Apache 2.4.41"},
    )
    store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"state": "closed", "version": "Apache 2.4.41"},
    )

    contradictions = store.contradictions_for_mission()

    assert contradictions
    assert "state changed" in contradictions[0].contradiction


def test_evidence_graph_store_detects_service_mismatch(tmp_path):
    store = EvidenceGraphStore(tmp_path / "intel.sqlite", mission_id="m1")
    store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"service": "http", "state": "open"},
    )
    store.add_evidence(
        entity="service",
        value="10.0.0.5:80/tcp",
        source_plugin="nmap",
        payload={"service": "ssh", "state": "open"},
    )
    contradictions = store.contradictions_for_mission()
    assert contradictions
    assert "service changed" in contradictions[0].contradiction


def test_evidence_graph_store_prunes_expired_records(tmp_path):
    db_path = tmp_path / "intel.sqlite"
    store = EvidenceGraphStore(db_path, mission_id="m1")
    record = store.add_evidence(
        entity="host",
        value="10.0.0.5",
        source_plugin="nmap",
        payload={"alive": True},
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE evidence SET timestamp = ?, ttl_seconds = ? WHERE record_id = ?",
            ("2000-01-01T00:00:00+00:00", 1, record.record_id),
        )
        conn.commit()
    removed = store.prune_expired()
    assert removed == 1
    assert store.active_evidence() == []
