import os

import pytest

from workers.auth import WorkerAuth


def test_worker_auth_rejects_weak_default_secret():
    with pytest.raises(ValueError):
        WorkerAuth("oracle-worker-secret")


def test_worker_auth_rejects_short_secret():
    with pytest.raises(ValueError):
        WorkerAuth("shortsecret")


def test_worker_auth_reads_env_secret(monkeypatch):
    monkeypatch.setenv("ORACLE_WORKER_SECRET", "very-strong-worker-secret-123")
    auth = WorkerAuth(None)
    signed = auth.sign({"ok": True}, timestamp="123")
    assert auth.verify({"ok": True}, signed)


def test_worker_auth_allows_insecure_only_when_flag_enabled(monkeypatch):
    monkeypatch.setenv("ORACLE_ALLOW_INSECURE_WORKER_SECRET", "1")
    auth = WorkerAuth("")
    signed = auth.sign({"ok": True}, timestamp="123")
    assert auth.verify({"ok": True}, signed)
