import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rich.console import Console

from oracle.cli.main import _run_startup_preflight
from oracle.plugins.base import ToolPlugin


class _StubPlugin(ToolPlugin):
    name = "stub"
    description = "stub"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "echo ok"

    def parse(self, stdout, stderr):
        return {"status": "ok", "data": {}, "error": ""}


class _StubRegistry:
    def __init__(self):
        self._plugin = _StubPlugin()

    def available_map(self):
        return {"stub": True}


def test_startup_preflight_blocks_on_required_failure(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text("[workers]\nshared_secret = \"short\"\n", encoding="utf-8")
    console = Console(record=True, width=140)

    rc = _run_startup_preflight(
        registry=_StubRegistry(),
        web_enabled=False,
        web_auth_token="",
        web_auth_user="",
        web_auth_pass="",
        config_path=config_path,
        console_obj=console,
    )

    assert rc == 1
    assert "Startup preflight failed on required checks." in console.export_text()


def test_startup_preflight_allows_non_required_warning(tmp_path, monkeypatch):
    import oracle.runtime.config_validator as config_validator

    config_path = tmp_path / "config.toml"
    config_path.write_text("[workers]\nshared_secret = \"very-strong-worker-secret-123\"\n", encoding="utf-8")
    monkeypatch.setattr(config_validator, "ModelRouter", lambda _ai: type("R", (), {"active": lambda self: object(), "fallback": lambda self: object(), "backend": "ollama"})())
    console = Console(record=True, width=140)

    rc = _run_startup_preflight(
        registry=_StubRegistry(),
        web_enabled=False,
        web_auth_token="",
        web_auth_user="",
        web_auth_pass="",
        config_path=config_path,
        console_obj=console,
    )

    assert rc == 0

