"""Evidence export and IOC bundling."""

from __future__ import annotations

from typing import Any, Dict, List


def build_evidence_export(graph_dict: Dict[str, Any]) -> Dict[str, Any]:
    evidence = list(graph_dict.get("evidence", []))
    findings = list(graph_dict.get("findings", []))
    indicators: List[Dict[str, Any]] = []
    for finding in findings:
        host = finding.get("host", "")
        port = finding.get("port", 0)
        if host:
            indicators.append(
                {
                    "type": "network_service",
                    "value": f"{host}:{port}",
                    "severity": finding.get("severity", "INFO"),
                    "title": finding.get("title", ""),
                }
            )
    return {
        "evidence_records": evidence,
        "iocs": indicators,
        "count": len(evidence),
    }
