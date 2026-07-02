"""ORACLE — Tests  (tests/test_executor.py)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.models import Action
from oracle.plugins.base import PluginRegistry
from oracle.plugins.nmap import NmapPlugin
from oracle.plugins.http import HttpPlugin
from oracle.plugins.fuzz import FuzzPlugin
from oracle.runtime.executor import Executor


def make_registry() -> PluginRegistry:
    reg = PluginRegistry()
    reg._plugins["nmap"] = NmapPlugin()
    reg._plugins["http"] = HttpPlugin()
    reg._plugins["fuzz"] = FuzzPlugin()
    return reg


# ── Plugin build ──────────────────────────────────────────────────────────────

def test_nmap_build():
    p = NmapPlugin()
    cmd = p.build("192.168.1.1", {"ports": "22,80"})
    assert "nmap" in cmd
    assert "192.168.1.1" in cmd
    assert "22,80" in cmd

def test_http_build():
    p = HttpPlugin()
    cmd = p.build("192.168.1.1", {"port": 80, "path": "/robots.txt"})
    assert "curl" in cmd
    assert "/robots.txt" in cmd

def test_fuzz_build_contains_target():
    p = FuzzPlugin()
    cmd = p.build("192.168.1.1", {"port": 80})
    assert "192.168.1.1" in cmd


# ── Plugin parse ──────────────────────────────────────────────────────────────

def test_nmap_parse():
    p = NmapPlugin()
    sample = "80/tcp   open  http    Apache httpd 2.4.41\n22/tcp  open  ssh     OpenSSH 8.2"
    result = p.parse(sample, "")
    assert len(result["data"]["ports"]) == 2
    assert result["data"]["ports"][0]["port"] == 80
    assert result["data"]["ports"][0]["service"] == "http"

def test_nmap_parse_empty():
    p = NmapPlugin()
    result = p.parse("", "")
    assert result["data"]["ports"] == []

def test_http_parse_status():
    p = HttpPlugin()
    sample = "HTTP/1.1 200 OK\nServer: Apache/2.4.41\nContent-Type: text/html\n\n---STATS---\n200 1234 0.432"
    result = p.parse(sample, "")
    assert result["data"]["status_code"] == 200
    assert "apache" in result["data"]["server"].lower()

def test_fuzz_parse_gobuster():
    p = FuzzPlugin()
    sample = "/admin                 (Status: 200) [Size: 1234]\n/uploads               (Status: 301) [Size: 0]"
    result = p.parse(sample, "")
    assert result["data"]["count"] == 2
    paths = [i["path"] for i in result["data"]["paths"]]
    assert "/admin" in paths


# ── Executor ──────────────────────────────────────────────────────────────────

def test_executor_unknown_tool():
    reg = make_registry()
    ex = Executor(reg)
    action = Action(tool="unknown_tool", target="127.0.0.1", args={})
    result = ex.run(action)
    assert result.returncode == -1
    assert "Unknown tool" in result.stderr


def test_executor_parse_error_does_not_crash(monkeypatch):
    from oracle.plugins.base import ToolPlugin

    class BadParse(ToolPlugin):
        name = "badparse"
        description = "bad"
        category = "util"
        requires_binary = None

        def build(self, target, args):
            return "echo ok"

        def parse(self, stdout, stderr):
            raise RuntimeError("boom")

    reg = make_registry()
    reg._plugins["badparse"] = BadParse()
    ex = Executor(reg)
    action = Action(tool="badparse", target="127.0.0.1", args={})
    result = ex.run(action)
    assert result.returncode == 0
    assert "parse_error" in (result.parsed or {})

def test_executor_build_command():
    reg = make_registry()
    ex = Executor(reg)
    action = Action(tool="nmap", target="127.0.0.1", args={"ports": "80"})
    cmd = ex.build_command(action)
    assert "nmap" in cmd
    assert "127.0.0.1" in cmd
"""ORACLE — Tests  (tests/test_graph.py)"""


# ── Graph tests ───────────────────────────────────────────────────────────────

import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.memory.storage import Storage
from oracle.memory.graph import KnowledgeGraph
from oracle.core.models import Action, ActionResult


def make_graph(tmp_path=None):
    if tmp_path is None:
        tmp_path = Path(tempfile.mkdtemp())
    storage = Storage(tmp_path)
    return KnowledgeGraph("test_mission", storage)


def test_add_host():
    g = make_graph()
    h = g.add_host("192.168.1.1", os_guess="Linux")
    assert "192.168.1.1" in g.hosts
    assert g.hosts["192.168.1.1"].os_guess == "Linux"


def test_add_host_dedup():
    g = make_graph()
    g.add_host("10.0.0.1")
    g.add_host("10.0.0.1", os_guess="Windows")
    assert len(g.hosts) == 1
    assert g.hosts["10.0.0.1"].os_guess == "Windows"


def test_add_finding():
    g = make_graph()
    f = g.add_finding(severity="HIGH", title="Test finding", host="10.0.0.1", port=80)
    assert len(g.findings) == 1
    assert f.severity == "HIGH"


def test_finding_dedup():
    g = make_graph()
    g.add_finding(title="Same", host="10.0.0.1", port=80, severity="INFO")
    g.add_finding(title="Same", host="10.0.0.1", port=80, severity="INFO")
    assert len(g.findings) == 1


def test_top_findings_sorted():
    g = make_graph()
    g.add_finding(severity="LOW",      title="Low",      host="h", port=1)
    g.add_finding(severity="CRITICAL", title="Critical", host="h", port=2)
    g.add_finding(severity="HIGH",     title="High",     host="h", port=3)
    top = g.top_findings(3)
    assert top[0].severity == "CRITICAL"
    assert top[1].severity == "HIGH"


def test_directive():
    g = make_graph()
    g.add_directive("Focus on port 443")
    assert len(g.recent_directives()) == 1
    assert "443" in g.recent_directives()[0]


def test_ingest_nmap_result():
    g = make_graph()
    action = Action(tool="nmap", target="10.0.0.5", args={})
    result = ActionResult(
        action=action,
        stdout="",
        stderr="",
        returncode=0,
        duration=1.0,
        parsed={
            "_target": "10.0.0.5",
            "os_guess": "Linux",
            "ports": [
                {"port": 80, "service": "http", "version": "Apache", "protocol": "tcp"},
                {"port": 22, "service": "ssh",  "version": "OpenSSH", "protocol": "tcp"},
            ]
        }
    )
    new = g.ingest_result(result)
    assert "10.0.0.5" in g.hosts
    assert len(g.hosts["10.0.0.5"].ports) == 2
    assert any(f.port == 80 for f in new)


def test_ingest_nmap_enriches_offline_cves(tmp_path):
    from oracle.core.intelligence import IntelligenceEngine

    intel = IntelligenceEngine(online_enabled=False)
    g = KnowledgeGraph("test_mission", Storage(tmp_path), intel=intel)

    action = Action(tool="nmap", target="10.0.0.5", args={})
    result = ActionResult(
        action=action,
        stdout="",
        stderr="",
        returncode=0,
        duration=1.0,
        parsed={
            "_target": "10.0.0.5",
            "os_guess": "Linux",
            "ports": [
                {"port": 80, "service": "http", "version": "Apache httpd 2.4.49", "protocol": "tcp"},
            ],
        },
    )

    g.ingest_result(result)
    pi = g.hosts["10.0.0.5"].ports[0]
    assert "CVE-2021-41773" in pi.cves


def test_save_and_reload(tmp_path):
    g = make_graph(tmp_path)
    g.add_host("1.2.3.4", os_guess="FreeBSD")
    g.add_finding(severity="MEDIUM", title="Test", host="1.2.3.4", port=443)
    g.add_chat_message("operator", "hello", ts="00:00:01")
    g.save()

    g2 = make_graph(tmp_path)
    assert "1.2.3.4" in g2.hosts
    assert g2.hosts["1.2.3.4"].os_guess == "FreeBSD"
    assert len(g2.findings) == 1
    assert g2.recent_chat(5)[-1]["text"] == "hello"


def test_summary_format():
    g = make_graph()
    g.add_host("10.0.0.1", os_guess="Linux")
    summary = g.summary()
    assert "10.0.0.1" in summary
    assert "GRAPH" in summary
