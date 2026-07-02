"""Structured intelligence report synthesis for final mission output."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from core.attackgraph import attack_graph_summary, build_attack_graph
from core.correlation import build_attack_candidates, graph_state_summary, rank_attack_paths


SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_host(host: Dict[str, Any], findings: List[Dict[str, Any]], host_ip: str) -> float:
    score = 0.0
    ports = list(host.get("ports", []) or [])
    score += min(len(ports), 20) * 0.02
    for finding in findings:
        if str(finding.get("host", "")) != host_ip:
            continue
        sev = str(finding.get("severity", "INFO")).upper()
        score += SEVERITY_RANK.get(sev, 1) * 0.12
    return round(min(score, 1.0), 3)


def _ranked_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = sorted(
        [dict(item) for item in findings],
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("severity", "INFO")).upper(), 1),
            str(item.get("title", "")),
        ),
        reverse=True,
    )
    return ranked


def _top_hosts(hosts: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    top: List[Dict[str, Any]] = []
    for ip, host in hosts.items():
        ports = list(host.get("ports", []) or [])
        top.append(
            {
                "host": ip,
                "risk_score": _score_host(host, findings, ip),
                "open_ports": len([port for port in ports if str(port.get("state", "open")).lower() == "open"]),
                "services": sorted(
                    list({str(port.get("service", "")).lower() for port in ports if str(port.get("service", "")).strip()})[:15]
                ),
                "os_guess": str(host.get("os_guess", "")),
            }
        )
    return sorted(top, key=lambda item: (float(item["risk_score"]), item["open_ports"]), reverse=True)[:10]


def _remediation_lines(findings: List[Dict[str, Any]], attack_paths: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    by_service: Dict[str, int] = {}
    for finding in findings:
        title = str(finding.get("title", "")).lower()
        if "ssh" in title:
            by_service["ssh"] = by_service.get("ssh", 0) + 1
        if "smb" in title:
            by_service["smb"] = by_service.get("smb", 0) + 1
        if "web" in title or "http" in title or "/admin" in title:
            by_service["web"] = by_service.get("web", 0) + 1
    if by_service.get("web"):
        lines.append("Harden web entry points: remove exposed admin/debug paths and enforce authentication controls.")
    if by_service.get("smb"):
        lines.append("Restrict SMB exposure to trusted segments and enforce strong authentication + signing.")
    if by_service.get("ssh"):
        lines.append("Apply SSH hardening: key-only auth, rate limits, and strict account policy.")
    if attack_paths:
        lines.append("Prioritize mitigation for the top correlated attack paths before expanding scope scans.")
    if not lines:
        lines.append("Maintain least-privilege network exposure and continue deterministic validation cycles.")
    return lines


def _evidence_summary(graph_dict: Dict[str, Any]) -> Dict[str, Any]:
    evidence = [dict(item) for item in list(graph_dict.get("evidence", []) or []) if isinstance(item, dict)]
    by_entity: Dict[str, int] = {}
    contradictions = 0
    high_confidence = 0
    for record in evidence:
        entity = str(record.get("entity", "") or "unknown")
        by_entity[entity] = by_entity.get(entity, 0) + 1
        if str(record.get("contradiction", "") or "").strip():
            contradictions += 1
        if float(record.get("confidence", 0.0) or 0.0) >= 0.85:
            high_confidence += 1
    return {
        "count": len(evidence),
        "high_confidence": high_confidence,
        "contradictions": contradictions,
        "by_entity": dict(sorted(by_entity.items())),
    }


def build_intelligence_report(
    mission_name: str,
    graph_dict: Dict[str, Any],
    *,
    mission_snapshot: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    hosts = dict(graph_dict.get("hosts", {}) or {})
    findings = _ranked_findings(list(graph_dict.get("findings", []) or []))
    stats = dict(graph_dict.get("stats", {}) or {})
    state_summary = graph_state_summary(_GraphProxy(graph_dict))
    evidence_summary = _evidence_summary(graph_dict)

    attack_graph = build_attack_graph(graph_dict)
    attack_graph_summary_data = attack_graph_summary(attack_graph)
    attack_paths = list(attack_graph_summary_data.get("top_paths", []) or [])
    top_hosts = _top_hosts(hosts, findings)
    remediation_text = _remediation_lines(findings, attack_paths)

    executive_summary_lines = [
        f"Mission {mission_name} identified {stats.get('hosts', len(hosts))} host(s) and {stats.get('findings', len(findings))} finding(s).",
        f"Critical findings: {stats.get('critical', 0)}; High findings: {stats.get('high', 0)}.",
    ]
    if attack_paths:
        top_path = attack_paths[0]
        executive_summary_lines.append(
            f"Top correlated attack path score {float(top_path.get('score', 0.0)):.2f}: {' -> '.join((top_path.get('path', []) or [])[:4])}."
        )
    if evidence_summary["contradictions"]:
        executive_summary_lines.append(
            f"Evidence graph recorded {evidence_summary['contradictions']} contradiction(s); confidence was reduced on affected paths."
        )

    machine_package = {
        "report_schema_version": "phase1.v1",
        "mission": mission_name,
        "generated_at": _utc_now(),
        "stats": stats,
        "graph_state": state_summary,
        "evidence_summary": evidence_summary,
        "ranked_findings": findings[:50],
        "top_hosts": top_hosts,
        "attack_graph": attack_graph,
        "attack_graph_summary": attack_graph_summary_data,
        "remediation": remediation_text,
        "snapshot": mission_snapshot or {},
    }

    return {
        "report_schema_version": machine_package["report_schema_version"],
        "mission": mission_name,
        "generated_at": machine_package["generated_at"],
        "executive_summary": "\n".join(executive_summary_lines),
        "graph_state": state_summary,
        "evidence_summary": evidence_summary,
        "ranked_findings": findings[:25],
        "top_hosts": top_hosts,
        "attack_graph": attack_graph,
        "attack_graph_summary": attack_graph_summary_data,
        "remediation_text": remediation_text,
        "machine_package": machine_package,
    }


class _GraphProxy:
    """Adapter so correlation helpers can read a dict snapshot like a graph object."""

    def __init__(self, graph_dict: Dict[str, Any]):
        self._graph_dict = graph_dict
        self.hosts = self._convert_hosts(dict(graph_dict.get("hosts", {}) or {}))
        self.findings = self._convert_findings(list(graph_dict.get("findings", []) or []))

    @staticmethod
    def _convert_hosts(hosts: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for ip, host in hosts.items():
            record = type("HostRecordProxy", (), {})()
            record.ip = ip
            record.ports = []
            for port in list(host.get("ports", []) or []):
                p = type("PortInfoProxy", (), {})()
                p.port = int(port.get("port", 0) or 0)
                p.service = str(port.get("service", "") or "")
                p.protocol = str(port.get("protocol", "tcp") or "tcp")
                p.state = str(port.get("state", "open") or "open")
                p.version = str(port.get("version", "") or "")
                p.cves = list(port.get("cves", []) or [])
                p.cvss = port.get("cvss")
                record.ports.append(p)
            out[ip] = record
        return out

    @staticmethod
    def _convert_findings(findings: List[Dict[str, Any]]) -> List[Any]:
        out: List[Any] = []
        for idx, finding in enumerate(findings):
            f = type("FindingProxy", (), {})()
            f.fid = str(finding.get("fid", f"f{idx}"))
            f.host = str(finding.get("host", "") or "")
            f.port = int(finding.get("port", 0) or 0)
            f.severity = str(finding.get("severity", "INFO") or "INFO")
            f.title = str(finding.get("title", "") or "")
            f.description = str(finding.get("description", "") or "")
            f.evidence = str(finding.get("evidence", "") or "")
            out.append(f)
        return out
