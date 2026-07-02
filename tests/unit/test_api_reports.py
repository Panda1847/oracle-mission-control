import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from api.reports import generate_report_bundle


def test_generate_report_bundle_matches_canonical_reporting_shape():
    graph = {
        "phase": "REPORTING",
        "status": "complete",
        "stats": {"hosts": 1, "findings": 1, "critical": 0, "high": 0},
        "hosts": {"10.0.0.1": {"ports": [{"port": 80, "service": "http"}], "os_guess": "Linux"}},
        "findings": [{"severity": "INFO", "title": "Web service", "host": "10.0.0.1", "port": 80}],
        "evidence": [{"entity": "host", "value": "10.0.0.1"}],
    }

    bundle = generate_report_bundle("m1", graph)

    assert bundle["summary"]["mission"] == "m1"
    assert bundle["evidence"]["count"] == 1
    assert bundle["intelligence_report"]["machine_package"]["mission"] == "m1"
    assert bundle["json"]["intelligence_report"]["machine_package"]["mission"] == "m1"
    assert bundle["package_bytes"] > 0
    assert bundle["package_manifest"]["mission"] == "m1"
