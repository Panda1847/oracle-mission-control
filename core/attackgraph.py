"""Canonical weighted attack-graph synthesis."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from core.correlation import build_attack_candidates, confidence_propagation, link_related_findings, rank_attack_paths


SEVERITY_RISK = {
    "CRITICAL": 1.0,
    "HIGH": 0.84,
    "MEDIUM": 0.66,
    "LOW": 0.48,
    "INFO": 0.28,
}

TOPOLOGY_EDGE_BASE = 0.14
CORRELATION_EDGE_BASE = 0.22


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    if value < low:
        return low
    if value > high:
        return high
    return value


def _graph_snapshot(graph: Any) -> Dict[str, Any]:
    if isinstance(graph, dict):
        return dict(graph)
    if hasattr(graph, "to_dict"):
        try:
            snapshot = graph.to_dict()
        except Exception:
            snapshot = {}
        if isinstance(snapshot, dict):
            return snapshot
    return {}


def _host_from_evidence(record: Dict[str, Any]) -> str:
    payload = dict(record.get("payload", {}) or {})
    host = str(payload.get("host", "") or "").strip()
    if host:
        return host
    entity = str(record.get("entity", "") or "").strip().lower()
    value = str(record.get("value", "") or "").strip()
    if entity == "host":
        return value
    if ":" in value:
        return value.split(":", 1)[0].strip()
    return ""


def _evidence_indexes(snapshot: Dict[str, Any]) -> tuple[Dict[str, int], Dict[tuple[str, int], int], set[tuple[str, int]]]:
    by_host: Dict[str, int] = {}
    by_socket: Dict[tuple[str, int], int] = {}
    contradictions: set[tuple[str, int]] = set()
    for item in list(snapshot.get("evidence", []) or []):
        if not isinstance(item, dict):
            continue
        host = _host_from_evidence(item)
        payload = dict(item.get("payload", {}) or {})
        port = int(payload.get("port", 0) or 0)
        if host:
            by_host[host] = by_host.get(host, 0) + 1
        if host and port > 0:
            key = (host, port)
            by_socket[key] = by_socket.get(key, 0) + 1
            if str(item.get("contradiction", "") or "").strip():
                contradictions.add(key)
    return by_host, by_socket, contradictions


def _findings_indexes(snapshot: Dict[str, Any]) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[tuple[str, int], List[Dict[str, Any]]]]:
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    by_socket: Dict[tuple[str, int], List[Dict[str, Any]]] = {}
    for item in list(snapshot.get("findings", []) or []):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "") or "").strip()
        port = int(item.get("port", 0) or 0)
        if host:
            by_host.setdefault(host, []).append(dict(item))
        if host and port > 0:
            by_socket.setdefault((host, port), []).append(dict(item))
    return by_host, by_socket


def _fallback_topology(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    hosts = dict(snapshot.get("hosts", {}) or {})
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set[str] = set()

    for ip, host in sorted(hosts.items()):
        subnet = "unknown"
        parts = ip.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            subnet = ".".join(parts[:3]) + ".0/24"
        subnet_id = f"subnet:{subnet}"
        if subnet_id not in seen_nodes:
            seen_nodes.add(subnet_id)
            nodes.append({"id": subnet_id, "label": subnet, "kind": "subnet", "severity": "INFO"})

        host_id = f"host:{ip}"
        if host_id not in seen_nodes:
            seen_nodes.add(host_id)
            nodes.append({"id": host_id, "label": ip, "kind": "host", "severity": "INFO"})
        edges.append({"from": subnet_id, "to": host_id, "kind": "contains"})

        for port in list(host.get("ports", []) or []):
            service = str(port.get("service", "") or "").lower().strip() or "unknown"
            port_num = int(port.get("port", 0) or 0)
            service_id = f"svc:{ip}:{service}:{port_num}"
            if service_id not in seen_nodes:
                seen_nodes.add(service_id)
                nodes.append(
                    {
                        "id": service_id,
                        "label": f"{service}:{port_num}",
                        "kind": "service",
                        "severity": "INFO",
                    }
                )
            edges.append({"from": host_id, "to": service_id, "kind": "exposes"})

    return {"nodes": nodes, "edges": edges}


def _host_port_service_map(snapshot: Dict[str, Any]) -> Dict[tuple[str, int], str]:
    mapping: Dict[tuple[str, int], str] = {}
    for host, record in dict(snapshot.get("hosts", {}) or {}).items():
        for port in list(record.get("ports", []) or []):
            port_num = int(port.get("port", 0) or 0)
            if port_num <= 0:
                continue
            service = str(port.get("service", "") or "").lower().strip() or "unknown"
            mapping[(host, port_num)] = service
    return mapping


def _path_id(path: Sequence[str]) -> str:
    return "path:" + "->".join(str(item) for item in path)


def _node_id_from_token(token: str, host_port_services: Dict[tuple[str, int], str]) -> str:
    parts = str(token).split(":")
    if len(parts) >= 3 and parts[1] == "credential-context":
        return f"cred:{parts[0]}"
    if len(parts) >= 3 and parts[1] == "web":
        host = parts[0]
        port = int(parts[2] or 0)
        service = host_port_services.get((host, port), "http")
        return f"svc:{host}:{service}:{port}"
    if len(parts) >= 3:
        host = parts[0]
        service = parts[1]
        port = int(parts[2] or 0)
        return f"svc:{host}:{service}:{port}"
    return f"path:{token}"


def _path_label_from_token(token: str) -> str:
    parts = str(token).split(":")
    if len(parts) >= 3 and parts[1] == "credential-context":
        return f"{parts[0]} credentials"
    if len(parts) >= 3 and parts[1] == "web":
        return f"web:{parts[2]}"
    if len(parts) >= 3:
        return f"{parts[1]}:{parts[2]}"
    return str(token)


def _path_kind_from_token(token: str) -> str:
    parts = str(token).split(":")
    if len(parts) >= 3 and parts[1] == "credential-context":
        return "credential_context"
    if len(parts) >= 3:
        return "service"
    return "path_segment"


def _severity_for_findings(items: Iterable[Dict[str, Any]]) -> str:
    best = "INFO"
    best_score = 0.0
    for item in items:
        sev = str(item.get("severity", "INFO") or "INFO").upper()
        score = SEVERITY_RISK.get(sev, SEVERITY_RISK["INFO"])
        if score > best_score:
            best = sev
            best_score = score
    return best


def _severity_risk(items: Iterable[Dict[str, Any]]) -> float:
    scores = [SEVERITY_RISK.get(str(item.get("severity", "INFO") or "INFO").upper(), SEVERITY_RISK["INFO"]) for item in items]
    if not scores:
        return 0.0
    return max(scores)


def _node_base_risk(
    node: Dict[str, Any],
    findings_by_host: Dict[str, List[Dict[str, Any]]],
    findings_by_socket: Dict[tuple[str, int], List[Dict[str, Any]]],
    evidence_by_host: Dict[str, int],
    evidence_by_socket: Dict[tuple[str, int], int],
    contradictions: set[tuple[str, int]],
) -> tuple[float, int]:
    node_id = str(node.get("id", "") or "")
    parts = node_id.split(":")
    evidence_count = 0
    if node_id.startswith("host:") and len(parts) >= 2:
        host = parts[1]
        findings = findings_by_host.get(host, [])
        evidence_count = evidence_by_host.get(host, 0)
        risk = _severity_risk(findings)
        risk += min(evidence_count, 5) * 0.04
        return _clamp(risk), evidence_count
    if node_id.startswith("svc:") and len(parts) >= 4:
        host = parts[1]
        try:
            port = int(parts[-1] or 0)
        except ValueError:
            port = 0
        findings = findings_by_socket.get((host, port), [])
        evidence_count = evidence_by_socket.get((host, port), 0)
        risk = _severity_risk(findings)
        risk += min(evidence_count, 4) * 0.05
        if (host, port) in contradictions:
            risk -= 0.08
        return _clamp(risk), evidence_count
    return 0.0, 0


def _build_graph_proxy(snapshot: Dict[str, Any]) -> Any:
    return _GraphProxy(snapshot)


def build_attack_graph(graph: Any) -> Dict[str, Any]:
    snapshot = _graph_snapshot(graph)
    topology = dict(snapshot.get("topology", {}) or {})
    if not topology.get("nodes") and not topology.get("edges"):
        topology = _fallback_topology(snapshot)

    findings_by_host, findings_by_socket = _findings_indexes(snapshot)
    evidence_by_host, evidence_by_socket, contradictions = _evidence_indexes(snapshot)
    host_port_services = _host_port_service_map(snapshot)

    graph_proxy = graph if hasattr(graph, "hosts") and hasattr(graph, "findings") else _build_graph_proxy(snapshot)
    links = link_related_findings(graph_proxy)
    propagated_confidence = confidence_propagation(graph_proxy, links)
    ranked_paths = rank_attack_paths(build_attack_candidates(graph_proxy))

    node_map: Dict[str, Dict[str, Any]] = {}
    for raw_node in list(topology.get("nodes", []) or []):
        if not isinstance(raw_node, dict):
            continue
        node = dict(raw_node)
        node_id = str(node.get("id", "") or "")
        if not node_id:
            continue
        risk, evidence_count = _node_base_risk(
            node,
            findings_by_host,
            findings_by_socket,
            evidence_by_host,
            evidence_by_socket,
            contradictions,
        )
        node_map[node_id] = {
            "id": node_id,
            "label": str(node.get("label", node_id) or node_id),
            "kind": str(node.get("kind", "node") or "node"),
            "severity": str(node.get("severity", "INFO") or "INFO"),
            "weight": round(risk, 3),
            "risk_score": round(risk, 3),
            "evidence_count": int(evidence_count),
        }

    edge_map: Dict[str, Dict[str, Any]] = {}
    for raw_edge in list(topology.get("edges", []) or []):
        if not isinstance(raw_edge, dict):
            continue
        src = str(raw_edge.get("from", "") or "")
        dst = str(raw_edge.get("to", "") or "")
        kind = str(raw_edge.get("kind", "linked") or "linked")
        if not src or not dst:
            continue
        src_weight = float(node_map.get(src, {}).get("weight", 0.0) or 0.0)
        dst_weight = float(node_map.get(dst, {}).get("weight", 0.0) or 0.0)
        edge_id = f"topology:{kind}:{src}->{dst}"
        edge_map[edge_id] = {
            "id": edge_id,
            "from": src,
            "to": dst,
            "kind": kind,
            "weight": round(_clamp(TOPOLOGY_EDGE_BASE + ((src_weight + dst_weight) / 4.0)), 3),
            "reasoning": f"topology:{kind}",
            "supporting_finding_ids": [],
        }

    max_path_score = max((float(item.get("score", 0.0) or 0.0) for item in ranked_paths), default=0.0)
    top_paths: List[Dict[str, Any]] = []

    for index, path_item in enumerate(ranked_paths):
        raw_path = [str(item) for item in list(path_item.get("path", []) or []) if str(item).strip()]
        if not raw_path:
            continue
        node_ids: List[str] = []
        finding_ids = sorted({str(item) for item in list(path_item.get("finding_ids", []) or []) if str(item).strip()})
        score = _clamp(float(path_item.get("score", 0.0) or 0.0))
        normalized_score = score if max_path_score <= 0 else round(score / max_path_score, 3)

        for token in raw_path:
            node_id = _node_id_from_token(token, host_port_services)
            node = node_map.get(node_id)
            if node is None:
                host = token.split(":", 1)[0]
                severity = _severity_for_findings(findings_by_host.get(host, []))
                evidence_count = evidence_by_host.get(host, 0)
                node = {
                    "id": node_id,
                    "label": _path_label_from_token(token),
                    "kind": _path_kind_from_token(token),
                    "severity": severity,
                    "weight": 0.0,
                    "risk_score": 0.0,
                    "evidence_count": int(evidence_count),
                }
                node_map[node_id] = node

            path_boost = 0.12 + (score * 0.32)
            if finding_ids:
                path_boost += min(len(finding_ids), 4) * 0.015
            node["weight"] = round(_clamp(float(node.get("weight", 0.0) or 0.0) + path_boost), 3)
            node["risk_score"] = round(_clamp(max(float(node.get("risk_score", 0.0) or 0.0), score)), 3)
            node_ids.append(node_id)

        for src, dst in zip(node_ids, node_ids[1:]):
            edge_id = f"correlated:{src}->{dst}"
            edge = edge_map.get(edge_id)
            if edge is None:
                edge = {
                    "id": edge_id,
                    "from": src,
                    "to": dst,
                    "kind": "correlated_path",
                    "weight": 0.0,
                    "reasoning": str(path_item.get("reason", "correlated attack path") or "correlated attack path"),
                    "supporting_finding_ids": [],
                }
                edge_map[edge_id] = edge
            edge["weight"] = round(_clamp(max(float(edge.get("weight", 0.0) or 0.0), CORRELATION_EDGE_BASE + (score * 0.62))), 3)
            edge["supporting_finding_ids"] = sorted(set(edge.get("supporting_finding_ids", []) or []).union(finding_ids))

        top_paths.append(
            {
                "path_id": f"{_path_id(raw_path)}:{index}",
                "path": raw_path,
                "node_ids": node_ids,
                "score": round(score, 3),
                "normalized_score": normalized_score,
                "reason": str(path_item.get("reason", "") or ""),
                "finding_ids": finding_ids,
            }
        )

    ordered_nodes = sorted(node_map.values(), key=lambda item: (str(item.get("kind", "")), str(item.get("id", ""))))
    ordered_edges = sorted(edge_map.values(), key=lambda item: (str(item.get("kind", "")), str(item.get("id", ""))))
    weighted_edges = sum(1 for edge in ordered_edges if float(edge.get("weight", 0.0) or 0.0) > TOPOLOGY_EDGE_BASE)

    summary = {
        "nodes": len(ordered_nodes),
        "edges": len(ordered_edges),
        "candidate_count": len(top_paths),
        "highest_path_score": round(max_path_score, 3),
        "weighted_edges": int(weighted_edges),
    }

    return {
        "summary": summary,
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "top_paths": top_paths[:10],
    }


def project_attack_path(graph: Any, path: Sequence[str]) -> Dict[str, Any]:
    snapshot = _graph_snapshot(graph)
    host_port_services = _host_port_service_map(snapshot)
    tokens = [str(item) for item in list(path or []) if str(item).strip()]
    return {
        "path_id": _path_id(tokens),
        "path": tokens,
        "node_ids": [_node_id_from_token(token, host_port_services) for token in tokens],
    }


def attack_graph_summary(attack_graph: Dict[str, Any], *, top_paths_limit: int = 10) -> Dict[str, Any]:
    graph_obj = dict(attack_graph or {})
    summary = dict(graph_obj.get("summary", {}) or {})
    nodes = list(graph_obj.get("nodes", []) or [])
    edges = list(graph_obj.get("edges", []) or [])
    top_paths = list(graph_obj.get("top_paths", []) or [])[:top_paths_limit]
    return {
        "nodes": int(summary.get("nodes", len(nodes)) or 0),
        "edges": int(summary.get("edges", len(edges)) or 0),
        "candidate_count": int(summary.get("candidate_count", len(top_paths)) or 0),
        "highest_path_score": float(summary.get("highest_path_score", 0.0) or 0.0),
        "weighted_edges": int(summary.get("weighted_edges", 0) or 0),
        "top_paths": top_paths,
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
                item = type("PortInfoProxy", (), {})()
                item.port = int(port.get("port", 0) or 0)
                item.service = str(port.get("service", "") or "")
                item.protocol = str(port.get("protocol", "tcp") or "tcp")
                item.state = str(port.get("state", "open") or "open")
                item.version = str(port.get("version", "") or "")
                item.cves = list(port.get("cves", []) or [])
                item.cvss = port.get("cvss")
                record.ports.append(item)
            out[ip] = record
        return out

    @staticmethod
    def _convert_findings(findings: List[Dict[str, Any]]) -> List[Any]:
        out: List[Any] = []
        for idx, finding in enumerate(findings):
            item = type("FindingProxy", (), {})()
            item.fid = str(finding.get("fid", f"f{idx}"))
            item.host = str(finding.get("host", "") or "")
            item.port = int(finding.get("port", 0) or 0)
            item.severity = str(finding.get("severity", "INFO") or "INFO")
            item.title = str(finding.get("title", "") or "")
            item.description = str(finding.get("description", "") or "")
            item.evidence = str(finding.get("evidence", "") or "")
            out.append(item)
        return out
