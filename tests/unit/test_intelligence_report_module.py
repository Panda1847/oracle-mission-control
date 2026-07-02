from core.reporting import build_intelligence_report


def test_build_intelligence_report_contains_required_sections():
    graph = {
        "stats": {"hosts": 2, "findings": 3, "critical": 0, "high": 1},
        "hosts": {
            "10.0.0.1": {
                "os_guess": "Linux",
                "ports": [
                    {"port": 80, "service": "http", "state": "open"},
                    {"port": 445, "service": "smb", "state": "open"},
                ],
            },
            "10.0.0.2": {
                "os_guess": "Linux",
                "ports": [{"port": 22, "service": "ssh", "state": "open"}],
            },
        },
        "findings": [
            {"fid": "f1", "severity": "HIGH", "title": "Web path: /admin [200]", "host": "10.0.0.1", "port": 80},
            {"fid": "f2", "severity": "MEDIUM", "title": "Service: SMB on 10.0.0.1:445", "host": "10.0.0.1", "port": 445},
            {"fid": "f3", "severity": "INFO", "title": "Service: SSH on 10.0.0.2:22", "host": "10.0.0.2", "port": 22},
        ],
        "topology": {"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"from": "a", "to": "b"}]},
    }

    report = build_intelligence_report("m-intel", graph, mission_snapshot={"phase": "REPORTING"})

    assert report["mission"] == "m-intel"
    assert report["executive_summary"]
    assert report["report_schema_version"] == "phase1.v1"
    assert report["graph_state"]["hosts"] == 2
    assert report["evidence_summary"]["count"] == 0
    assert report["ranked_findings"]
    assert report["top_hosts"]
    assert report["attack_graph"]["summary"]["nodes"] == len(report["attack_graph"]["nodes"])
    assert report["attack_graph_summary"]["nodes"] == report["attack_graph"]["summary"]["nodes"]
    assert report["remediation_text"]
    assert report["machine_package"]["snapshot"]["phase"] == "REPORTING"
    assert report["machine_package"]["attack_graph"] == report["attack_graph"]
    assert report["machine_package"]["attack_graph_summary"]["candidate_count"] >= 0
