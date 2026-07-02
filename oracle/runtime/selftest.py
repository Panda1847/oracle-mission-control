"""Integrated runtime self-test harness."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from core.orchestrator.event_bus import EventBus
from storage.db import Database
from workers.auth import WorkerAuth

from ..core.ai import OracleAI
from ..core.config import load_config
from ..runtime.config_validator import RuntimeConfigValidator


@dataclass(frozen=True)
class SelfTestResult:
    check: str
    detail: str
    ok: bool
    required: bool = True


def _plugin_smoke(registry, name: str, target: str, args: dict[str, Any], sample_stdout: str) -> SelfTestResult:
    plugin = registry.get(name) if registry else None
    if plugin is None:
        return SelfTestResult(f"plugin:{name}", "plugin missing", False, True)
    try:
        command = plugin.build(target, args)
        parsed = plugin.parse(sample_stdout, "")
    except Exception as exc:
        return SelfTestResult(f"plugin:{name}", f"smoke failed: {exc}", False, True)
    if not isinstance(command, str) or not command.strip():
        return SelfTestResult(f"plugin:{name}", "build returned empty command", False, True)
    if not isinstance(parsed, dict):
        return SelfTestResult(f"plugin:{name}", "parse did not return object", False, True)
    return SelfTestResult(f"plugin:{name}", "smoke passed", True, True)


def _event_bus_smoke() -> SelfTestResult:
    bus = EventBus()
    received: list[dict[str, Any]] = []

    def _cb(payload):
        received.append(dict(payload or {}))

    try:
        bus.subscribe("selftest.event", _cb)
        bus.publish("selftest.event", {"ok": True}, trace_id="selftest")
        deadline = time.time() + 1.5
        while time.time() < deadline and not received:
            time.sleep(0.01)
        if not received:
            return SelfTestResult("eventbus", "subscriber did not receive event in time", False, True)
        return SelfTestResult("eventbus", "publish/subscribe loop passed", True, True)
    finally:
        if hasattr(bus, "close"):
            bus.close()


def _db_smoke(path: Path) -> SelfTestResult:
    try:
        db = Database(path)
        db.upsert_mission("selftest", "running", "INIT", "{}")
        db.add_artifact("selftest", "json", str(path), "application/json")
        rows = db.artifacts_for("selftest")
        if not rows:
            return SelfTestResult("db", "artifact readback empty", False, True)
        return SelfTestResult("db", "sqlite metadata write/read passed", True, True)
    except Exception as exc:
        return SelfTestResult("db", f"sqlite check failed: {exc}", False, True)


def _ai_smoke() -> SelfTestResult:
    from core.ai.model_router import ModelRouter

    router = ModelRouter(OracleAI())
    active = router.active()
    backend = str(getattr(router, "backend", "auto"))
    if active is router.fallback() and backend not in {"deterministic"}:
        return SelfTestResult("ai backend", f"{backend} unavailable, fallback active", False, False)
    return SelfTestResult("ai backend", f"{backend} backend usable", True, False)


def run_selftest(console: Console, *, registry, data_dir: Path, log_dir: Path) -> int:
    cfg = load_config()
    results: list[SelfTestResult] = []

    validator = RuntimeConfigValidator(
        registry=registry,
        data_dir=data_dir,
        log_dir=log_dir,
        config=cfg,
        web_enabled=False,
    )
    for item in validator.run():
        results.append(SelfTestResult(item.name, item.detail, item.ok, item.kind == "required"))

    results.extend(
        [
            _plugin_smoke(
                registry,
                "nmap",
                "127.0.0.1",
                {"ports": "22,80", "timing": "T3"},
                "22/tcp open ssh OpenSSH 9.0\n80/tcp open http Apache 2.4\nOS details: Linux",
            ),
            _plugin_smoke(
                registry,
                "http",
                "127.0.0.1",
                {"port": 80, "path": "/", "method": "GET"},
                "HTTP/1.1 200 OK\nServer: Apache\nX-Powered-By: PHP\n",
            ),
            _plugin_smoke(
                registry,
                "fuzz",
                "127.0.0.1",
                {"port": 80},
                "/admin                 (Status: 200)\n/backup                 (Status: 403)\n",
            ),
            _event_bus_smoke(),
            _db_smoke(Path(data_dir) / "selftest.sqlite"),
            _ai_smoke(),
        ]
    )

    # Worker auth roundtrip smoke using resolved secret.
    try:
        workers_cfg = cfg.get("workers", {}) if isinstance(cfg.get("workers"), dict) else {}
        auth = WorkerAuth(str(workers_cfg.get("shared_secret", "")))
        signed = auth.sign({"selftest": True}, timestamp="1")
        ok = auth.verify({"selftest": True}, signed)
        results.append(SelfTestResult("worker auth", "hmac sign/verify", ok, True))
    except Exception as exc:
        results.append(SelfTestResult("worker auth", str(exc), False, True))

    table = Table(title="ORACLE Self-Test", border_style="green")
    table.add_column("Check", style="cyan")
    table.add_column("Detail", style="white")
    table.add_column("OK", style="green")
    table.add_column("Required", style="yellow")

    hard_fail = False
    for result in results:
        if result.required and not result.ok:
            hard_fail = True
        table.add_row(result.check, result.detail, "✓" if result.ok else "✗", "yes" if result.required else "no")

    console.print(table)
    if hard_fail:
        console.print("[red]Self-test failed on required checks.[/red]")
        return 1
    console.print("[green]Self-test passed for required checks.[/green]")
    return 0
