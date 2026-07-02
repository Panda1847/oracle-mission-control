"""Evidence control-plane serializers."""

from __future__ import annotations

from typing import Any, Dict


def evidence_snapshot(graph) -> Dict[str, Any]:
    if graph is None:
        return {"items": [], "stats": {}, "contradictions": []}
    graph_dict = graph.to_dict()
    return {
        "items": graph_dict.get("evidence", []),
        "stats": graph.evidence_stats(),
        "contradictions": graph.contradictions(),
    }

