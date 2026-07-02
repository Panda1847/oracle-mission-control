"""SQLite-backed evidence intelligence graph store."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from contextlib import closing
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .confidence_engine import ConfidenceEngine
from .contradiction_detector import ContradictionDetector
from .deduplicator import Deduplicator
from .evidence_linker import EvidenceLinker
from .provenance import ProvenanceBuilder
from .ttl_decay import TTLDecayPolicy


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class EvidenceRecord:
    entity: str
    value: str
    source_plugin: str
    mission_id: str
    confidence: float
    timestamp: str
    ttl_seconds: int
    related_entities: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    contradiction: str = ""
    record_id: str = field(default_factory=lambda: uuid4().hex)


class EvidenceGraphStore:
    """Stores evidence, links, and contradictions for a mission."""

    def __init__(self, db_path: Path, mission_id: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.mission_id = mission_id
        self.confidence = ConfidenceEngine()
        self.ttl = TTLDecayPolicy()
        self.provenance = ProvenanceBuilder(self.db_path.with_name(f"{self.mission_id}_provenance.jsonl"))
        self.deduplicator = Deduplicator()
        self.contradictions = ContradictionDetector()
        self.linker = EvidenceLinker()
        self._init_db()

    def add_evidence(
        self,
        entity: str,
        value: str,
        source_plugin: str,
        observed_confidence: float | None = None,
        payload: Optional[Dict[str, Any]] = None,
        related_entities: Optional[List[str]] = None,
    ) -> EvidenceRecord:
        payload = dict(payload or {})
        related_entities = list(related_entities or [])
        observed_at = _utcnow()
        record = EvidenceRecord(
            entity=entity,
            value=value,
            source_plugin=source_plugin,
            mission_id=self.mission_id,
            confidence=self.confidence.score(source_plugin, observed_confidence),
            timestamp=observed_at.isoformat(),
            ttl_seconds=self.ttl.ttl_for(entity),
            related_entities=related_entities,
            payload=payload,
            provenance=self.provenance.build(source_plugin, self.mission_id, payload),
        )
        existing = self.get_by_key(self.deduplicator.key_for(record))
        contradiction = self.contradictions.detect(existing, record)
        if contradiction:
            record.contradiction = contradiction
        if existing:
            merged = self.deduplicator.merge(existing, record, self.confidence.merge(existing.confidence, record.confidence))
            self._upsert(merged)
            self._sync_links(merged)
            return merged
        self._upsert(record)
        self._sync_links(record)
        return record

    def get_by_key(self, key: str) -> Optional[EvidenceRecord]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT record_id, entity, value, source_plugin, mission_id, confidence, timestamp, ttl_seconds, related_entities, payload, provenance, contradiction "
                "FROM evidence WHERE mission_id = ? AND evidence_key = ?",
                (self.mission_id, key),
            ).fetchone()
        return self._row_to_record(row)

    def active_evidence(self) -> List[EvidenceRecord]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT record_id, entity, value, source_plugin, mission_id, confidence, timestamp, ttl_seconds, related_entities, payload, provenance, contradiction "
                "FROM evidence WHERE mission_id = ?",
                (self.mission_id,),
            ).fetchall()
        now = _utcnow()
        records: List[EvidenceRecord] = []
        for row in rows:
            record = self._row_to_record(row)
            if record is None:
                continue
            observed_at = datetime.fromisoformat(record.timestamp)
            record.confidence = self.ttl.decay(record.confidence, observed_at, record.ttl_seconds, now=now)
            records.append(record)
        return records

    def prune_expired(self) -> int:
        now = _utcnow()
        expired_ids: List[str] = []
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT record_id, timestamp, ttl_seconds FROM evidence WHERE mission_id = ?",
                (self.mission_id,),
            ).fetchall()
        for row in rows:
            record_id = str(row[0])
            try:
                observed_at = datetime.fromisoformat(str(row[1]))
            except Exception:
                continue
            ttl_seconds = int(row[2] or 0)
            if self.ttl.is_expired(observed_at, ttl_seconds, now=now):
                expired_ids.append(record_id)
        if not expired_ids:
            return 0

        with closing(sqlite3.connect(self.db_path)) as conn:
            for record_id in expired_ids:
                conn.execute("DELETE FROM evidence WHERE record_id = ?", (record_id,))
                conn.execute("DELETE FROM links WHERE source_id = ? OR target_id = ?", (record_id, record_id))
            conn.commit()
        return len(expired_ids)

    def contradictions_for_mission(self) -> List[EvidenceRecord]:
        return [record for record in self.active_evidence() if record.contradiction]

    def related(self, record_id: str) -> List[Dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT source_id, target_id, relation_score FROM links WHERE source_id = ? OR target_id = ?",
                (record_id, record_id),
            ).fetchall()
        return [{"source_id": row[0], "target_id": row[1], "relation_score": row[2]} for row in rows]

    def stats(self) -> Dict[str, Any]:
        records = self.active_evidence()
        return {
            "records": len(records),
            "contradictions": len([record for record in records if record.contradiction]),
            "high_confidence": len([record for record in records if record.confidence >= 0.85]),
        }

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    record_id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    evidence_key TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_plugin TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    related_entities TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    contradiction TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS links (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation_score REAL NOT NULL,
                    PRIMARY KEY (source_id, target_id)
                )
                """
            )
            conn.commit()

    def _upsert(self, record: EvidenceRecord):
        evidence_key = self.deduplicator.key_for(record)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO evidence (
                    record_id, mission_id, evidence_key, entity, value, source_plugin, confidence, timestamp,
                    ttl_seconds, related_entities, payload, provenance, contradiction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    mission_id=excluded.mission_id,
                    evidence_key=excluded.evidence_key,
                    entity=excluded.entity,
                    value=excluded.value,
                    source_plugin=excluded.source_plugin,
                    confidence=excluded.confidence,
                    timestamp=excluded.timestamp,
                    ttl_seconds=excluded.ttl_seconds,
                    related_entities=excluded.related_entities,
                    payload=excluded.payload,
                    provenance=excluded.provenance,
                    contradiction=excluded.contradiction
                """,
                (
                    record.record_id,
                    record.mission_id,
                    evidence_key,
                    record.entity,
                    record.value,
                    record.source_plugin,
                    record.confidence,
                    record.timestamp,
                    record.ttl_seconds,
                    json.dumps(record.related_entities),
                    json.dumps(record.payload),
                    json.dumps(record.provenance),
                    record.contradiction,
                ),
            )
            conn.commit()

    def _sync_links(self, record: EvidenceRecord):
        links = self.linker.links_for(record)
        with closing(sqlite3.connect(self.db_path)) as conn:
            for source_id, target_id, score in links:
                conn.execute(
                    "INSERT OR REPLACE INTO links (source_id, target_id, relation_score) VALUES (?, ?, ?)",
                    (source_id, target_id, score),
                )
            conn.commit()

    def _row_to_record(self, row) -> Optional[EvidenceRecord]:
        if row is None:
            return None
        return EvidenceRecord(
            record_id=row[0],
            entity=row[1],
            value=row[2],
            source_plugin=row[3],
            mission_id=row[4],
            confidence=float(row[5]),
            timestamp=row[6],
            ttl_seconds=int(row[7]),
            related_entities=json.loads(row[8]),
            payload=json.loads(row[9]),
            provenance=json.loads(row[10]),
            contradiction=row[11],
        )
