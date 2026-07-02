"""Enterprise mission summary generation."""

from __future__ import annotations

from typing import Any, Dict, List


def build_mission_summary(mission_name: str, graph_dict: Dict[str, Any], *, narrative: str = "") -> Dict[str, Any]:
    stats = graph_dict.get("stats", {})
    findings = list(graph_dict.get("findings", []))
    rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    top_findings = sorted(findings, key=lambda item: rank.get(item.get("severity", "INFO"), 0), reverse=True)[:10]
    hosts = graph_dict.get("hosts", {})

    executive_lines: List[str] = [
        f"Mission {mission_name} completed with {stats.get('hosts', 0)} discovered hosts and {stats.get('findings', 0)} findings.",
        f"Critical findings: {stats.get('critical', 0)}. High findings: {stats.get('high', 0)}.",
    ]
    for finding in top_findings[:5]:
        executive_lines.append(
            f"- {finding.get('severity', 'INFO')}: {finding.get('title', '')} ({finding.get('host', '')}:{finding.get('port', 0)})"
        )
    if narrative:
        executive_lines.append("")
        executive_lines.append(narrative.strip())

    attack_surface = []
    for ip, host in list(hosts.items())[:50]:
        attack_surface.append(
            {
                "host": ip,
                "ports": [f"{port.get('port')}/{port.get('service', '?')}" for port in host.get("ports", [])[:12]],
                "os_guess": host.get("os_guess", ""),
            }
        )

    return {
        "mission": mission_name,
        "stats": stats,
        "executive_summary": "\n".join(executive_lines),
        "top_findings": top_findings,
        "attack_surface": attack_surface,
    }
