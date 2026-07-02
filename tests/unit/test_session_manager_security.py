import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.runtime.sessions import SessionManager


def test_session_manager_rejects_unsafe_shell_tokens(monkeypatch):
    manager = SessionManager()
    monkeypatch.setattr(manager._runtime, "ensure_started", lambda: False)

    with pytest.raises(ValueError):
        manager.execute("echo ok && id", timeout=2)


def test_session_manager_executes_safe_command(monkeypatch):
    manager = SessionManager()
    monkeypatch.setattr(manager._runtime, "ensure_started", lambda: False)

    output = manager.execute("printf hello", timeout=2)
    assert "hello" in output
