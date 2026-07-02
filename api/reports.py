"""Artifact and report control-plane serializers."""

from __future__ import annotations

from typing import Any, Dict, List

from core.reporting import (
    build_evidence_export,
    build_intelligence_report,
    build_json_export,
    build_mission_summary,
    build_pdf_report,
)
from export.package import build_mission_package


def report_snapshot(artifact_router, *, download_prefix: str = "") -> List[Dict[str, Any]]:
    if artifact_router is None:
        return []
    items = artifact_router.list_artifacts()
    if not download_prefix:
        return items
    base = str(download_prefix.rstrip("/"))
    enriched: List[Dict[str, Any]] = []
    for item in items:
        payload = dict(item)
        relative_path = str(item.get("relative_path", "") or "")
        if relative_path:
            payload["download_url"] = f"{base}/{relative_path}"
        enriched.append(payload)
    return enriched


def generate_report_bundle(mission_name: str, graph_dict: Dict[str, Any]) -> Dict[str, Any]:
    mission_snapshot = {
        "phase": graph_dict.get("phase", ""),
        "status": graph_dict.get("status", ""),
    }
    summary = build_mission_summary(mission_name, graph_dict)
    evidence = build_evidence_export(graph_dict)
    intelligence_report = build_intelligence_report(
        mission_name,
        graph_dict,
        mission_snapshot=mission_snapshot,
    )
    report_json = build_json_export(
        mission_name,
        summary,
        evidence,
        mission_snapshot=mission_snapshot,
        intelligence_report=intelligence_report,
    )
    report_pdf = build_pdf_report(summary)
    package = build_mission_package(
        mission_name,
        mission_snapshot=mission_snapshot,
        graph_snapshot=graph_dict,
        summary=summary,
        evidence=evidence,
        intelligence_report=intelligence_report,
        bundle=report_json,
        pdf_report=report_pdf,
        replay_artifacts=(),
    )
    return {
        "summary": summary,
        "evidence": evidence,
        "intelligence_report": intelligence_report,
        "json": report_json,
        "pdf_bytes": len(report_pdf),
        "package_bytes": len(package.payload),
        "package_manifest": package.manifest,
    }
