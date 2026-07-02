import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.correlation import (
    build_attack_candidates,
    confidence_propagation,
    link_related_findings,
    rank_attack_paths,
)
from oracle.memory.graph import KnowledgeGraph
from oracle.memory.storage import Storage


def make_graph(tmp_path):
    return KnowledgeGraph("correlation_test", Storage(tmp_path))


def test_confidence_propagation_raises_related_info_confidence(tmp_path):
    graph = make_graph(tmp_path)
    graph.add_host("10.10.10.10")
    graph.add_finding(
        severity="HIGH",
        title="Web path: /admin [200]",
        description="admin panel",
        host="10.10.10.10",
        port=80,
        plugin="fuzz",
    )
    info_finding = graph.add_finding(
        severity="INFO",
        title="Service: SMB on 10.10.10.10:445",
        description="smb visible",
        host="10.10.10.10",
        port=445,
        plugin="nmap",
    )

    links = link_related_findings(graph)
    confidence = confidence_propagation(graph, links)

    assert info_finding.fid in confidence
    assert confidence[info_finding.fid] > 0.35


def test_build_attack_candidates_generates_ranked_paths(tmp_path):
    graph = make_graph(tmp_path)
    host = graph.add_host("10.10.10.15")
    host.add_port(80, service="http", version="nginx")
    host.add_port(445, service="smb", version="Samba")
    graph.add_finding(
        severity="MEDIUM",
        title="Web path: /admin [200]",
        description="admin panel exposed",
        host="10.10.10.15",
        port=80,
        plugin="fuzz",
    )

    candidates = rank_attack_paths(build_attack_candidates(graph))

    assert candidates
    assert candidates[0]["score"] >= 0.4
    chain = " ".join(candidates[0]["path"])
    assert "10.10.10.15:web:80" in chain
    assert "10.10.10.15:smb:445" in chain


def test_build_attack_candidates_uses_evidence_confidence_and_contradictions(tmp_path):
    graph = make_graph(tmp_path)
    host = graph.add_host("10.10.10.25")
    host.add_port(445, service="smb", version="Samba")
    graph.add_finding(
        severity="MEDIUM",
        title="Service: SMB on 10.10.10.25:445",
        description="relay surface",
        host="10.10.10.25",
        port=445,
        plugin="nmap",
    )
    graph._evidence.add_evidence(
        entity="service",
        value="10.10.10.25:445/tcp",
        source_plugin="nmap",
        observed_confidence=0.97,
        payload={"host": "10.10.10.25", "port": 445, "service": "smb"},
    )

    strong_candidates = rank_attack_paths(build_attack_candidates(graph))

    graph._evidence.add_evidence(
        entity="service",
        value="10.10.10.25:445/tcp",
        source_plugin="nmap",
        observed_confidence=0.30,
        payload={"host": "10.10.10.25", "port": 445, "service": "ssh"},
    )

    contradicted_candidates = rank_attack_paths(build_attack_candidates(graph))

    assert strong_candidates
    assert contradicted_candidates
    assert strong_candidates[0]["score"] >= contradicted_candidates[0]["score"]
    assert "contradictory evidence" in contradicted_candidates[0]["reason"]
