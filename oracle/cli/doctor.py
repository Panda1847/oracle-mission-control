from __future__ import annotations

import json
import os
import platform
import sys
import urllib.request
from pathlib import Path
from typing import Any, Tuple

import yaml
from rich.console import Console
from rich.table import Table

from ..core.config import load_config
from ..plugins.base import PluginRegistry, ToolPlugin
from ..runtime.config_validator import RuntimeConfigValidator


def _check_import(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def _load_ai_config() -> dict:
    root = Path(__file__).resolve().parents[2]
    config_path = root / "config" / "ai.yaml"
    if not config_path.exists():
        return {}
    try:
        parsed = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _check_ollama(host: str, model: str, timeout_s: float = 2.0) -> bool:
    url = f"{host.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=max(0.2, float(timeout_s))) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False

    models = payload.get("models", []) if isinstance(payload, dict) else []
    names = set()
    if isinstance(models, list):
        for item in models:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or item.get("model", "")).strip()
            if name:
                names.add(name)
    if model in names:
        return True
    base = model.split(":", 1)[0]
    return any(name.split(":", 1)[0] == base for name in names)


def run_doctor(
    console: Console,
    *,
    registry: PluginRegistry,
    data_dir: Path,
    log_dir: Path,
    strict: bool = False,
    web_enabled: bool = False,
    web_auth_token: str = "",
    web_auth_user: str = "",
    web_auth_pass: str = "",
) -> int:
    """
    Returns exit code: 0 = OK, 1 = missing required components.
    """
    # kind: required | optional | config (informational)
    rows: list[Tuple[str, str, bool, str]] = []

    rows.append(("python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", True, "required"))
    if sys.version_info < (3, 10):
        rows.append(("python>=3.10", "required", False, "required"))

    rows.append(("os", f"{platform.system()} {platform.release()}", True, "config"))

    # Check writeability
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        testfile = data_dir / ".writecheck"
        testfile.write_text("ok")
        testfile.unlink(missing_ok=True)
        rows.append(("data_dir writable", str(data_dir), True, "required"))
    except Exception:
        rows.append(("data_dir writable", str(data_dir), False, "required"))

    # Tool binaries
    avail = registry.available_map()
    for name, plugin in sorted(registry.all().items()):
        req = plugin.requires_binary
        ok = ToolPlugin.available(req)
        rows.append((f"tool:{name}", req or "(python-only)", ok, "required"))

    # Optional runtime features
    rows.append(("web deps", "flask + flask_socketio", _check_import("flask") and _check_import("flask_socketio"), "optional"))
    rows.append(("report deps", "jinja2", _check_import("jinja2"), "optional"))

    # AI backend checks (informational; not required for deterministic execution)
    ai_cfg = _load_ai_config()
    advisor = ai_cfg.get("advisor", {}) if isinstance(ai_cfg.get("advisor"), dict) else {}
    ollama = ai_cfg.get("ollama", {}) if isinstance(ai_cfg.get("ollama"), dict) else {}

    backend = str(
        os.environ.get("ORACLE_AI_BACKEND")
        or os.environ.get("ORACLE_ADVISOR_BACKEND")
        or advisor.get("backend", "auto")
    ).strip().lower()
    if backend not in {"auto", "anthropic", "ollama", "council", "deterministic"}:
        backend = "auto"

    anthropic_ready = bool(os.environ.get("ORACLE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))
    ollama_host = str(ollama.get("host", "http://127.0.0.1:11434")).strip()
    ollama_model = str(ollama.get("model", "llama3.2:3b")).strip()
    ollama_enabled = bool(ollama.get("enabled", True))
    ollama_ready = _check_ollama(ollama_host, ollama_model) if ollama_enabled else False

    if backend == "deterministic":
        advisor_ready = True
        advisor_detail = "deterministic fallback mode"
    elif backend == "anthropic":
        advisor_ready = anthropic_ready
        advisor_detail = "anthropic backend selected"
    elif backend == "ollama":
        advisor_ready = ollama_ready
        advisor_detail = f"ollama backend selected ({ollama_model})"
    elif backend == "council":
        advisor_ready = anthropic_ready or ollama_ready
        advisor_detail = "council backend selected (requires at least one ready model delegate)"
    else:
        advisor_ready = anthropic_ready or ollama_ready
        advisor_detail = "auto backend (anthropic or ollama)"

    rows.append(("advisor.backend", backend, True, "config"))
    rows.append(("advisor.ready", advisor_detail, advisor_ready, "config"))
    rows.append(("ORACLE_API_KEY", "set for Anthropic backend", anthropic_ready, "config"))
    rows.append(("ollama", f"{ollama_host} model={ollama_model}", ollama_ready, "config"))

    # External intel keys (not required)
    rows.append(("NVD_API_KEY", "optional for online CVE", bool(os.environ.get("NVD_API_KEY")), "config"))
    rows.append(("VULNERS_API_KEY", "optional for online CVE", bool(os.environ.get("VULNERS_API_KEY")), "config"))

    cfg: dict[str, Any] = {}
    try:
        cfg = load_config()
    except Exception:
        cfg = {}
    runtime_checks = RuntimeConfigValidator(
        registry=registry,
        data_dir=data_dir,
        log_dir=log_dir,
        config=cfg,
        web_enabled=web_enabled,
        web_auth_token=web_auth_token,
        web_auth_user=web_auth_user,
        web_auth_pass=web_auth_pass,
    ).run()
    existing = {name for name, *_ in rows}
    for check in runtime_checks:
        if check.name in existing:
            continue
        rows.append((check.name, check.detail, check.ok, check.kind))

    table = Table(title="ORACLE Doctor", border_style="green")
    table.add_column("Check", style="cyan")
    table.add_column("Detail", style="white")
    table.add_column("OK", style="green")

    hard_fail = False
    for check, detail, ok, kind in rows:
        if kind == "required" and ok is False:
            hard_fail = True
        if strict and kind == "optional" and ok is False:
            hard_fail = True
        table.add_row(check, str(detail), "✓" if ok else "✗")

    console.print(table)
    if hard_fail:
        console.print("[red]Doctor found missing required components.[/red]")
        return 1
    console.print("[green]Doctor checks look good.[/green]")
    return 0
