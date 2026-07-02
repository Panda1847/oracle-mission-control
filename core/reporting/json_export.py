"""JSON export helpers."""

from __future__ import annotations

from typing import Any, Dict


def build_json_export(
    mission_name: str,
    mission_summary: Dict[str, Any],
    evidence_export: Dict[str, Any],
    *,
    mission_snapshot: Dict[str, Any] | None = None,
    intelligence_report: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "mission": mission_name,
        "summary": mission_summary,
        "evidence": evidence_export,
        "intelligence_report": intelligence_report or {},
        "snapshot": mission_snapshot or {},
    }
