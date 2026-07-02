"""Correlation engine for exploit-path analysis in EXPLOIT_ANALYSIS phase."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence


SEVERITY_BASE = {
    "CRITICAL": 0.95,
    "HIGH": 0.82,
    "MEDIUM": 0.67,
    "LOW": 0.52,
    "INFO": 0.35,
}

PIVOT_SERVICES = {"smb", "mysql", "postgres", "mssql", "rdp", "ssh", "winrm", "ftp"}
WEB_SERVICES = {"http", "https"}

LIKELY_CREDENTIAL_HINTS = (
    "credential",
    "password",
    "default login",
    "admin panel",
    "exposed config",
    "token",
    "key",
)


@dataclass(frozen=True)
class AttackPath:
    """Correlation output used by exploit-analysis and planner reflections."""

    path: List[str]
    score: float
    reason: str
    finding_ids: List[str]


def _clamp(v: float, low: float = 0.0, high: float = 1.0) -> float:
    if v < low:
        return low
    if v > high:
        return high
    return v


def _host_ports(host_record) -> Iterable:
    return list(getattr(host_record, "ports", []) or [])


def _finding_key(finding, idx: int) -> str:
    return str(getattr(finding, "fid", "") or f"finding_{idx}")


def _graph_snapshot(graph) -> Dict[str, Any]:
    if isinstance(graph, dict):
        return dict(graph)
    if hasattr(graph, "to_dict"):
        try:
            snapshot = graph.to_dict()
            if isinstance(snapshot, dict):
                return snapshot
        except Exception:
            return {}
    return {}


def _evidence_records(graph) -> List[Dict[str, Any]]:
    snapshot = _graph_snapshot(graph)
    records = list(snapshot.get("evidence", []) or [])
    return [dict(record) for record in records if isinstance(record, dict)]


def graph_state_summary(graph) -> Dict[str, int]:
    snapshot = _graph_snapshot(graph)
    stats = dict(snapshot.get("stats", {}) or {})
    hosts = dict(getattr(graph, "hosts", {}) or {})
    findings = list(getattr(graph, "findings", []) or [])
    evidence = _evidence_records(graph)
    return {
        "hosts": int(stats.get("hosts", len(hosts)) or 0),
        "findings": int(stats.get("findings", len(findings)) or 0),
        "evidence_records": int(stats.get("evidence_records", len(evidence)) or 0),
        "contradictions": int(stats.get("contradictions", 0) or 0),
    }


def _host_from_evidence(record: Dict[str, Any]) -> str:
    payload = dict(record.get("payload", {}) or {})
    host = str(payload.get("host", "") or "").strip()
    if host:
        return host
    entity = str(record.get("entity", "") or "").strip().lower()
    value = str(record.get("value", "") or "").strip()
    if entity == "host":
        return value
    if value and ":" in value:
        return value.split(":", 1)[0].strip()
    return ""


def _evidence_context(graph) -> Dict[str, Dict[Any, Dict[str, float]]]:
    by_host: Dict[str, Dict[str, float]] = defaultdict(lambda: {"confidence_sum": 0.0, "count": 0.0, "contradictions": 0.0})
    by_socket: Dict[tuple[str, int], Dict[str, float]] = defaultdict(lambda: {"confidence_sum": 0.0, "count": 0.0, "contradictions": 0.0})

    for record in _evidence_records(graph):
        host = _host_from_evidence(record)
        if not host:
            continue
        confidence = _clamp(float(record.get("confidence", 0.0) or 0.0))
        contradiction = 1.0 if str(record.get("contradiction", "") or "").strip() else 0.0
        payload = dict(record.get("payload", {}) or {})
        port = int(payload.get("port", 0) or 0)

        bucket = by_host[host]
        bucket["confidence_sum"] += confidence
        bucket["count"] += 1.0
        bucket["contradictions"] += contradiction

        if port > 0:
            socket_bucket = by_socket[(host, port)]
            socket_bucket["confidence_sum"] += confidence
            socket_bucket["count"] += 1.0
            socket_bucket["contradictions"] += contradiction

    return {"by_host": by_host, "by_socket": by_socket}


def _evidence_score(host: str, port: int, evidence_context: Dict[str, Dict[Any, Dict[str, float]]]) -> tuple[float, float]:
    score = 0.0
    contradiction_penalty = 0.0
    bucket = evidence_context.get("by_socket", {}).get((host, port)) or evidence_context.get("by_host", {}).get(host)
    if not bucket:
        return score, contradiction_penalty
    count = float(bucket.get("count", 0.0) or 0.0)
    if count > 0:
        avg_confidence = float(bucket.get("confidence_sum", 0.0) or 0.0) / count
        score = avg_confidence * 0.12
        contradiction_penalty = min(float(bucket.get("contradictions", 0.0) or 0.0) * 0.06, 0.18)
    return score, contradiction_penalty


def link_related_findings(graph) -> Dict[str, List[str]]:
    """
    Link findings by host and host+port locality.

    Returns:
        {finding_id: [related_finding_id, ...], ...}
    """

    findings = list(getattr(graph, "findings", []) or [])
    by_host: Dict[str, List[tuple[str, Any]]] = {}
    by_socket: Dict[tuple[str, int], List[tuple[str, Any]]] = {}

    for idx, finding in enumerate(findings):
        fid = _finding_key(finding, idx)
        host = str(getattr(finding, "host", "") or "").strip()
        port = int(getattr(finding, "port", 0) or 0)
        if host:
            by_host.setdefault(host, []).append((fid, finding))
        if host and port > 0:
            by_socket.setdefault((host, port), []).append((fid, finding))

    linked: Dict[str, set[str]] = { _finding_key(f, i): set() for i, f in enumerate(findings) }

    for members in by_host.values():
        ids = [fid for fid, _ in members]
        for fid in ids:
            linked[fid].update(other for other in ids if other != fid)

    for members in by_socket.values():
        ids = [fid for fid, _ in members]
        for fid in ids:
            linked[fid].update(other for other in ids if other != fid)

    return {fid: sorted(related) for fid, related in linked.items()}


def confidence_propagation(graph, links: Dict[str, Sequence[str]] | None = None) -> Dict[str, float]:
    """
    Estimate finding confidence by propagating trust across related findings.
    """

    findings = list(getattr(graph, "findings", []) or [])
    if not findings:
        return {}

    links = links or link_related_findings(graph)
    confidence: Dict[str, float] = {}

    for idx, finding in enumerate(findings):
        fid = _finding_key(finding, idx)
        sev = str(getattr(finding, "severity", "INFO") or "INFO").upper()
        confidence[fid] = SEVERITY_BASE.get(sev, SEVERITY_BASE["INFO"])

    evidence_context = _evidence_context(graph)
    for idx, finding in enumerate(findings):
        fid = _finding_key(finding, idx)
        host = str(getattr(finding, "host", "") or "").strip()
        port = int(getattr(finding, "port", 0) or 0)
        evidence_boost, contradiction_penalty = _evidence_score(host, port, evidence_context)
        confidence[fid] = _clamp(confidence[fid] + evidence_boost - contradiction_penalty)

    for _ in range(2):
        updated = dict(confidence)
        for fid, neighbors in links.items():
            if not neighbors:
                continue
            neighbor_conf = [confidence.get(n, 0.0) for n in neighbors]
            if not neighbor_conf:
                continue
            propagated = (sum(neighbor_conf) / len(neighbor_conf)) * 0.85
            updated[fid] = _clamp(max(updated.get(fid, 0.0), propagated))
        confidence = updated

    return confidence


def _looks_like_credential_finding(finding) -> bool:
    title = str(getattr(finding, "title", "") or "").lower()
    desc = str(getattr(finding, "description", "") or "").lower()
    evidence = str(getattr(finding, "evidence", "") or "").lower()
    text = f"{title} {desc} {evidence}"
    return any(hint in text for hint in LIKELY_CREDENTIAL_HINTS)


def _service_score(service: str, cvss: float | None) -> float:
    s = service.lower().strip()
    base = 0.30
    if s in PIVOT_SERVICES:
        base += 0.18
    if s in {"smb", "rdp", "winrm"}:
        base += 0.10
    if cvss is not None:
        base += min(float(cvss), 10.0) / 28.0
    return _clamp(base)


def build_attack_candidates(graph) -> List[Dict[str, Any]]:
    """
    Build candidate exploit chains from graph hosts/findings/evidence.

    Output example:
      {
        "path": ["192.168.56.101:/admin", "mysql:3306", "192.168.56.102:smb:445"],
        "score": 0.87,
        "reason": "credential relay probable",
        "finding_ids": ["a1", "b2"]
      }
    """

    hosts = dict(getattr(graph, "hosts", {}) or {})
    findings = list(getattr(graph, "findings", []) or [])
    if not hosts:
        return []

    links = link_related_findings(graph)
    propagated = confidence_propagation(graph, links)
    evidence_context = _evidence_context(graph)

    host_findings: Dict[str, List[tuple[str, Any]]] = {}
    credential_findings: List[tuple[str, Any]] = []
    for idx, finding in enumerate(findings):
        fid = _finding_key(finding, idx)
        host = str(getattr(finding, "host", "") or "").strip()
        if host:
            host_findings.setdefault(host, []).append((fid, finding))
        if _looks_like_credential_finding(finding):
            credential_findings.append((fid, finding))

    candidates: List[AttackPath] = []

    for host, record in hosts.items():
        local = host_findings.get(host, [])
        web_local = [
            (fid, f)
            for fid, f in local
            if "web path" in str(getattr(f, "title", "")).lower()
            or int(getattr(f, "port", 0) or 0) in (80, 443)
        ]
        creds_local = [(fid, f) for fid, f in local if _looks_like_credential_finding(f)]

        for port in _host_ports(record):
            if str(getattr(port, "state", "open") or "open").lower() != "open":
                continue
            service = str(getattr(port, "service", "") or "").lower()
            if service not in PIVOT_SERVICES and not getattr(port, "cves", None):
                continue

            path_nodes: List[str] = []
            finding_ids: List[str] = []
            if web_local:
                top_web = sorted(
                    web_local,
                    key=lambda item: propagated.get(item[0], SEVERITY_BASE["INFO"]),
                    reverse=True,
                )[0]
                web_port = int(getattr(top_web[1], "port", 80) or 80)
                path_nodes.append(f"{host}:web:{web_port}")
                finding_ids.append(top_web[0])

            if creds_local:
                cred_top = sorted(
                    creds_local,
                    key=lambda item: propagated.get(item[0], SEVERITY_BASE["LOW"]),
                    reverse=True,
                )[0]
                finding_ids.append(cred_top[0])

            path_nodes.append(f"{host}:{service}:{int(getattr(port, 'port', 0) or 0)}")
            score = _service_score(service, getattr(port, "cvss", None))
            if finding_ids:
                f_score = sum(propagated.get(fid, 0.45) for fid in finding_ids) / len(finding_ids)
                score = _clamp((score * 0.55) + (f_score * 0.45))

            evidence_boost, contradiction_penalty = _evidence_score(host, int(getattr(port, "port", 0) or 0), evidence_context)
            score = _clamp(score + evidence_boost - contradiction_penalty)

            reason = "service pivot opportunity"
            if getattr(port, "cves", None):
                reason = "known CVE surface + service pivot"
                score = _clamp(score + 0.08)
            elif creds_local:
                reason = "credential relay probable"
                score = _clamp(score + 0.06)
            if contradiction_penalty > 0:
                reason = f"{reason}; contradictory evidence present"
            elif evidence_boost >= 0.08:
                reason = f"{reason}; corroborated by evidence graph"

            candidates.append(
                AttackPath(
                    path=path_nodes,
                    score=score,
                    reason=reason,
                    finding_ids=sorted(set(finding_ids)),
                )
            )

    # Cross-host credential relay candidates.
    if credential_findings and len(hosts) > 1:
        host_items = list(hosts.items())
        for cred_id, cred in credential_findings:
            src_host = str(getattr(cred, "host", "") or "").strip()
            if not src_host:
                continue
            for dst_host, dst_record in host_items:
                if dst_host == src_host:
                    continue
                for port in _host_ports(dst_record):
                    service = str(getattr(port, "service", "") or "").lower()
                    if service not in PIVOT_SERVICES:
                        continue
                    path = [
                        f"{src_host}:credential-context",
                        f"{dst_host}:{service}:{int(getattr(port, 'port', 0) or 0)}",
                    ]
                    base = propagated.get(cred_id, SEVERITY_BASE["MEDIUM"])
                    score = _clamp((base * 0.55) + (_service_score(service, getattr(port, "cvss", None)) * 0.45))
                    evidence_boost, contradiction_penalty = _evidence_score(
                        dst_host,
                        int(getattr(port, "port", 0) or 0),
                        evidence_context,
                    )
                    score = _clamp(score + evidence_boost - contradiction_penalty)
                    reason = "cross-host credential relay probable"
                    if contradiction_penalty > 0:
                        reason = f"{reason}; contradictory evidence present"
                    elif evidence_boost >= 0.08:
                        reason = f"{reason}; corroborated by evidence graph"
                    candidates.append(
                        AttackPath(
                            path=path,
                            score=score,
                            reason=reason,
                            finding_ids=[cred_id],
                        )
                    )

    dedup: Dict[tuple[str, ...], AttackPath] = {}
    for candidate in candidates:
        key = tuple(candidate.path)
        existing = dedup.get(key)
        if existing is None or candidate.score > existing.score:
            dedup[key] = candidate

    return [as_dict for as_dict in (path.__dict__ for path in dedup.values())]


def rank_attack_paths(candidates: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort attack paths by score and keep deterministic tie-breaks."""

    return sorted(
        [dict(candidate) for candidate in candidates],
        key=lambda item: (
            float(item.get("score", 0.0) or 0.0),
            len(item.get("path", []) or []),
            " ".join(item.get("path", []) or []),
        ),
        reverse=True,
    )
