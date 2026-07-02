import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console

from oracle.cli.doctor import run_doctor
from oracle.plugins.base import PluginRegistry, ToolPlugin


class _PyOnly(ToolPlugin):
    name = "pyonly"
    description = "pyonly"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "echo ok"

    def parse(self, stdout, stderr):
        return {}


def test_doctor_strict_does_not_require_api_keys(tmp_path, monkeypatch):
    reg = PluginRegistry()
    reg._plugins["pyonly"] = _PyOnly()

    # Ensure keys are missing
    monkeypatch.delenv("ORACLE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)

    c = Console(width=120, record=True)
    rc = run_doctor(c, registry=reg, data_dir=tmp_path / "d", log_dir=tmp_path / "l", strict=True)
    assert rc == 0


def test_doctor_strict_fails_on_missing_optional_dep(tmp_path, monkeypatch):
    import oracle.cli.doctor as doc

    reg = PluginRegistry()
    reg._plugins["pyonly"] = _PyOnly()

    monkeypatch.setattr(doc, "_check_import", lambda name: False if name == "jinja2" else True)
    c = Console(width=120, record=True)
    rc = run_doctor(c, registry=reg, data_dir=tmp_path / "d", log_dir=tmp_path / "l", strict=True)
    assert rc == 1


def test_doctor_accepts_ollama_backend_without_anthropic_key(tmp_path, monkeypatch):
    import oracle.cli.doctor as doc

    reg = PluginRegistry()
    reg._plugins["pyonly"] = _PyOnly()

    monkeypatch.delenv("ORACLE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        doc,
        "_load_ai_config",
        lambda: {
            "advisor": {"backend": "ollama"},
            "ollama": {"enabled": True, "host": "http://127.0.0.1:11434", "model": "llama3.2:3b"},
        },
    )
    monkeypatch.setattr(doc, "_check_ollama", lambda host, model, timeout_s=2.0: True)

    c = Console(width=120, record=True)
    rc = run_doctor(c, registry=reg, data_dir=tmp_path / "d", log_dir=tmp_path / "l", strict=True)
    assert rc == 0


def test_doctor_accepts_council_backend_with_ollama_delegate(tmp_path, monkeypatch):
    import oracle.cli.doctor as doc

    reg = PluginRegistry()
    reg._plugins["pyonly"] = _PyOnly()

    monkeypatch.delenv("ORACLE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        doc,
        "_load_ai_config",
        lambda: {
            "advisor": {"backend": "council"},
            "ollama": {"enabled": True, "host": "http://127.0.0.1:11434", "model": "llama3.2:3b"},
        },
    )
    monkeypatch.setattr(doc, "_check_ollama", lambda host, model, timeout_s=2.0: True)

    c = Console(width=120, record=True)
    rc = run_doctor(c, registry=reg, data_dir=tmp_path / "d", log_dir=tmp_path / "l", strict=True)
    assert rc == 0
