from core.reporting import (
    build_evidence_export,
    build_intelligence_report,
    build_json_export,
    build_mission_summary,
    build_pdf_report,
)


def test_reporting_bundle_generation():
    graph = {
        "stats": {"hosts": 1, "findings": 1, "critical": 0, "high": 0},
        "hosts": {"10.0.0.1": {"ports": [{"port": 80, "service": "http"}], "os_guess": "Linux"}},
        "findings": [{"severity": "INFO", "title": "Web service", "host": "10.0.0.1", "port": 80}],
        "evidence": [{"entity": "host", "value": "10.0.0.1"}],
    }
    summary = build_mission_summary("m1", graph)
    evidence = build_evidence_export(graph)
    intelligence = build_intelligence_report("m1", graph, mission_snapshot={"phase": "REPORTING"})
    exported = build_json_export("m1", summary, evidence, intelligence_report=intelligence)
    pdf = build_pdf_report(summary)

    assert summary["mission"] == "m1"
    assert evidence["count"] == 1
    assert intelligence["machine_package"]["mission"] == "m1"
    assert exported["mission"] == "m1"
    assert "intelligence_report" in exported
    assert pdf.startswith(b"%PDF-1.4")
