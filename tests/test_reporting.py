import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from oracle.core.reporting import deterministic_narrative, render_html_report


def test_html_report_renders_minimal():
    g = {
        "hosts": {
            "10.0.0.1": {"ports": [{"port": 80, "service": "http"}]},
        },
        "findings": [{"severity": "INFO", "title": "t", "host": "10.0.0.1", "port": 80}],
        "stats": {"hosts": 1, "findings": 1, "critical": 0, "high": 0},
    }
    narrative = deterministic_narrative(g, "m")
    html = render_html_report(graph_dict=g, mission_name="m", narrative=narrative)
    assert "ORACLE Report: m" in html
    assert "10.0.0.1" in html

