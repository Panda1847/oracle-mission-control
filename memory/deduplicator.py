"""Duplicate merge logic for evidence records."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph_store import EvidenceRecord


class Deduplicator:
    """Builds stable evidence keys and merges duplicates."""

    def key_for(self, record: "EvidenceRecord") -> str:
        return f"{record.entity}|{record.value}|{record.source_plugin}"

    def merge(self, existing: "EvidenceRecord", incoming: "EvidenceRecord", confidence: float) -> "EvidenceRecord":
        related = sorted(set(existing.related_entities + incoming.related_entities))
        payload = dict(existing.payload)
        payload.update(incoming.payload)
        provenance = dict(existing.provenance)
        provenance.update(incoming.provenance)
        return replace(
            existing,
            confidence=confidence,
            timestamp=incoming.timestamp,
            ttl_seconds=max(existing.ttl_seconds, incoming.ttl_seconds),
            related_entities=related,
            payload=payload,
            provenance=provenance,
            contradiction=existing.contradiction or incoming.contradiction,
        )
