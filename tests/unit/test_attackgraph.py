from core.attackgraph import attack_graph_summary, build_attack_graph


def _graph_snapshot(*, contradiction: bool = False):
    evidence = [
        {
            "entity": "service",
            "value": "10.0.0.5:445",
            "confidence": 0.92,
            "contradiction": "version mismatch" if contradiction else "",
            "payload": {"host": "10.0.0.5", "port": 445},
        }
    ]
    return {
        "hosts": {
            "10.0.0.5": {
                "os_guess": "Linux",
                "ports": [
                    {"port": 80, "service": "http", "state": "open"},
                    {"port": 445, "service": "smb", "state": "open"},
                ],
            },
            "10.0.0.9": {
                "os_guess": "Linux",
                "ports": [{"port": 22, "service": "ssh", "state": "open"}],
            },
        },
        "findings": [
            {
                "fid": "f1",
                "severity": "HIGH",
                "title": "Web path: /admin [200]",
                "description": "admin panel exposed",
                "host": "10.0.0.5",
                "port": 80,
                "evidence": "service:10.0.0.5:80",
            },
            {
                "fid": "f2",
                "severity": "MEDIUM",
                "title": "Service: SMB on 10.0.0.5:445",
                "description": "pivot service",
                "host": "10.0.0.5",
                "port": 445,
                "evidence": "service:10.0.0.5:445",
            },
            {
                "fid": "f3",
                "severity": "LOW",
                "title": "Default login exposed",
                "description": "credential context present",
                "host": "10.0.0.5",
                "port": 80,
                "evidence": "service:10.0.0.5:80",
            },
        ],
        "evidence": evidence,
        "topology": {
            "nodes": [
                {"id": "subnet:10.0.0.0/24", "label": "10.0.0.0/24", "kind": "subnet", "severity": "INFO"},
                {"id": "host:10.0.0.5", "label": "10.0.0.5", "kind": "host", "severity": "HIGH"},
                {"id": "svc:10.0.0.5:http:80", "label": "http:80", "kind": "service", "severity": "HIGH"},
                {"id": "svc:10.0.0.5:smb:445", "label": "smb:445", "kind": "service", "severity": "MEDIUM"},
                {"id": "host:10.0.0.9", "label": "10.0.0.9", "kind": "host", "severity": "LOW"},
                {"id": "svc:10.0.0.9:ssh:22", "label": "ssh:22", "kind": "service", "severity": "LOW"},
            ],
            "edges": [
                {"from": "subnet:10.0.0.0/24", "to": "host:10.0.0.5", "kind": "contains"},
                {"from": "host:10.0.0.5", "to": "svc:10.0.0.5:http:80", "kind": "exposes"},
                {"from": "host:10.0.0.5", "to": "svc:10.0.0.5:smb:445", "kind": "exposes"},
                {"from": "subnet:10.0.0.0/24", "to": "host:10.0.0.9", "kind": "contains"},
                {"from": "host:10.0.0.9", "to": "svc:10.0.0.9:ssh:22", "kind": "exposes"},
            ],
        },
    }


def test_build_attack_graph_is_deterministic_and_weighted():
    graph = _graph_snapshot()

    first = build_attack_graph(graph)
    second = build_attack_graph(graph)

    assert first == second
    assert first["summary"]["nodes"] == len(first["nodes"])
    assert first["summary"]["edges"] == len(first["edges"])
    assert first["summary"]["candidate_count"] >= 1
    assert first["summary"]["weighted_edges"] >= 1
    assert first["top_paths"]
    assert any(edge["kind"] == "correlated_path" for edge in first["edges"])
    smb_node = next(node for node in first["nodes"] if node["id"] == "svc:10.0.0.5:smb:445")
    assert smb_node["weight"] > 0.5


def test_attack_graph_contradictions_dampen_service_weight():
    clean_graph = build_attack_graph(_graph_snapshot(contradiction=False))
    contradicted_graph = build_attack_graph(_graph_snapshot(contradiction=True))

    clean_node = next(node for node in clean_graph["nodes"] if node["id"] == "svc:10.0.0.5:smb:445")
    contradicted_node = next(node for node in contradicted_graph["nodes"] if node["id"] == "svc:10.0.0.5:smb:445")

    assert contradicted_node["risk_score"] <= clean_node["risk_score"]
    assert contradicted_node["weight"] <= clean_node["weight"]


def test_attack_graph_summary_handles_topology_only_graph():
    graph = {
        "hosts": {"10.1.1.7": {"ports": []}},
        "findings": [],
        "topology": {
            "nodes": [{"id": "host:10.1.1.7", "label": "10.1.1.7", "kind": "host", "severity": "INFO"}],
            "edges": [],
        },
    }

    attack_graph = build_attack_graph(graph)
    summary = attack_graph_summary(attack_graph)

    assert summary["nodes"] == 1
    assert summary["edges"] == 0
    assert summary["candidate_count"] == 0
    assert summary["top_paths"] == []
