"""Relationship scoring between evidence records."""

from __future__ import annotations

from typing import Iterable, List, Tuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph_store import EvidenceRecord


class EvidenceLinker:
    """Builds graph links between related evidence entities."""

    def links_for(self, record: "EvidenceRecord") -> List[Tuple[str, str, float]]:
        links: List[Tuple[str, str, float]] = []
        for related in record.related_entities:
            links.append((record.record_id, related, 0.8))
        return links
