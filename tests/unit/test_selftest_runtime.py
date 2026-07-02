from rich.console import Console

from oracle.runtime.selftest import run_selftest
from oracle.plugins.base import ToolPlugin


class _SimplePlugin(ToolPlugin):
    def __init__(self, name):
        self.name = name
        self.description = name
        self.category = "util"
        self.requires_binary = None

    def build(self, target, args):
        return f"echo {self.name}"

    def parse(self, stdout, stderr):
        return {"status": "ok", "data": {}, "error": ""}


class _StubRegistry:
    def __init__(self):
        self.plugins = {
            "nmap": _SimplePlugin("nmap"),
            "http": _SimplePlugin("http"),
            "fuzz": _SimplePlugin("fuzz"),
        }

    def available_map(self):
        return {"nmap": True, "http": True, "fuzz": True}

    def get(self, name):
        return self.plugins.get(name)


def test_selftest_runs_readiness_matrix(tmp_path):
    console = Console(record=True, width=140)
    rc = run_selftest(
        console,
        registry=_StubRegistry(),
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )
    assert rc == 0
    rendered = console.export_text()
    assert "ORACLE Self-Test" in rendered
