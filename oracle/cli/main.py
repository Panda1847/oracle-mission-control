"""
ORACLE — Main CLI  (cli/main.py)
Entry point for all modes: demo, live, multi-agent, report.
"""
from __future__ import annotations
import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .. import __version__, get_build_identity
from ..core.models import Mission, Action
from ..core.ai import OracleAI
from ..core.engine import MissionEngine
from ..memory.graph import KnowledgeGraph
from ..memory.storage import Storage
from ..runtime.executor import Executor
from plugins.registry import PluginRegistry
from .dashboard import make_layout, render
from ..core.intelligence import IntelligenceEngine
from ..core.reporting import deterministic_narrative, render_html_report
from ..core.config import load_config, argparse_defaults_from_config
from core.policy.scope_guard import ScopeGuard
from core.ai.model_router import ModelRouter
from .doctor import run_doctor
from ..runtime.audit import AuditLogger, AuditConfig
from ..runtime.config_validator import RuntimeConfigValidator
from ..runtime.selftest import run_selftest
from ..runtime.webhook import WebhookNotifier, WebhookConfig
from .export import run as run_export
from .replay import run as run_replay

console = Console()

ORACLE_DIR   = Path.home() / ".oracle"
DATA_DIR     = ORACLE_DIR / "missions"
LOG_DIR      = ORACLE_DIR / "logs"

for _d in (DATA_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

VERSION_BASE = f"ORACLE v{__version__}"


class _WebHandle:
    def __init__(self, server=None, thread: threading.Thread | None = None):
        self.server = server
        self.thread = thread

    def shutdown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)

# ── Factory ───────────────────────────────────────────────────────────────────

def build_registry() -> PluginRegistry:
    reg = PluginRegistry()
    plugin_dir = Path(__file__).parent.parent / "plugins"
    count = reg.load_from_dir(plugin_dir)
    console.print(f"[dim]  Plugins loaded: {count}  ({', '.join(reg.all().keys())})[/dim]")
    return reg


def build_stack(mission: Mission, api_key: str, args=None):
    """Build the complete ORACLE runtime stack."""
    storage  = Storage(DATA_DIR)
    graph    = KnowledgeGraph(mission.name, storage)
    registry = build_registry()
    ai       = OracleAI(api_key=api_key)
    executor = Executor(registry)
    safety   = ScopeGuard(mission.scope)
    # Hybrid CVE engine (Tier 1 offline always; Tier 2 online optional).
    online = bool(getattr(args, "online_cve", False)) if args is not None else False
    intel = IntelligenceEngine(
        online_enabled=online,
        nvd_api_key=(getattr(args, "nvd_api_key", "") or os.environ.get("NVD_API_KEY", "")),
        vulners_api_key=(getattr(args, "vulners_api_key", "") or os.environ.get("VULNERS_API_KEY", "")),
        update_cb=graph.apply_cve_update,
    )
    graph.set_intel(intel)
    return graph, registry, ai, executor, safety


def _run_startup_preflight(
    *,
    registry,
    web_enabled: bool,
    web_auth_token: str,
    web_auth_user: str,
    web_auth_pass: str,
    config_path: Path | None = None,
    console_obj: Console | None = None,
) -> int:
    console_obj = console_obj or console
    validator = RuntimeConfigValidator(
        registry=registry,
        data_dir=DATA_DIR,
        log_dir=LOG_DIR,
        config=load_config(config_path),
        web_enabled=web_enabled,
        web_auth_token=web_auth_token,
        web_auth_user=web_auth_user,
        web_auth_pass=web_auth_pass,
    )
    checks = validator.run()
    blocking = [check for check in checks if check.kind == "required" and not check.ok]
    warnings = [check for check in checks if check.kind != "required" and not check.ok]
    if not blocking and not warnings:
        return 0

    table = Table(title="ORACLE Startup Preflight", border_style="green")
    table.add_column("Check", style="cyan")
    table.add_column("Detail", style="white")
    table.add_column("Kind", style="yellow")
    table.add_column("OK", style="green")
    for check in checks:
        if check.ok and not blocking:
            continue
        if check.ok and check.kind == "required":
            continue
        table.add_row(check.name, check.detail, check.kind, "✓" if check.ok else "✗")
    console_obj.print(table)
    if blocking:
        console_obj.print("[red]Startup preflight failed on required checks.[/red]")
        return 1
    console_obj.print("[yellow]Startup preflight warnings detected; continuing.[/yellow]")
    return 0


def _advisor_status_line(ai_client) -> str:
    router = ModelRouter(ai_client)
    active = router.active()
    backend = getattr(router, "backend", "auto")
    if active is router.fallback():
        if backend == "anthropic":
            return "AI advisory: Anthropic selected but API key missing, deterministic fallback active"
        if backend == "ollama":
            model = str(getattr(router.ollama, "model", "unknown"))
            return f"AI advisory: Ollama selected but unavailable (model={model}), deterministic fallback active"
        if backend == "council":
            return "AI advisory: Council selected but no model delegate is ready, deterministic fallback active"
        if backend == "deterministic":
            return "AI advisory: deterministic-only mode"
        return "AI advisory: no model backend ready, deterministic fallback active"
    if active is getattr(router, "council", None):
        primary = "anthropic" if getattr(router.client, "ready", False) else "none"
        secondary = "ollama" if getattr(router.ollama, "ready", False) else "none"
        return f"AI advisory: Council backend active (proposer/verifier={primary}, critic={secondary})"
    if active is getattr(router, "ollama", None):
        model = str(getattr(active, "model", "unknown"))
        return f"AI advisory: Ollama local backend active (model={model})"
    return "AI advisory: Anthropic backend active"


# ── Demo mode ─────────────────────────────────────────────────────────────────

def run_demo(args):
    from ..demos.demo_mission import DemoRunner
    mission = Mission(
        name="demo_network",
        scope=["127.0.0.1", "localhost"],
        objective="Demonstrate ORACLE capabilities in a safe simulated environment",
        profile="normal",
    )
    storage  = Storage(DATA_DIR)
    graph    = KnowledgeGraph(mission.name, storage)
    registry = build_registry()
    layout   = make_layout()

    runner = DemoRunner(graph, speed=args.demo_speed)
    last_action = None
    last_result = None
    web_handle = None
    if args.web:
        web_handle = _start_web(
            graph,
            mission,
            port=args.web_port,
            auth_token=(args.web_auth_token or ""),
            auth_user=(args.web_auth_user or ""),
            auth_pass=(args.web_auth_pass or ""),
            plugin_registry=registry,
        )

    console.print(Panel(
        "[bold green]🎬 ORACLE DEMO MODE\n"
        "[dim]Simulated mission — no API key or real tools required.[/dim][/bold green]",
        border_style="green"
    ))
    time.sleep(0.8)

    with Live(layout, refresh_per_second=4, screen=True) as live:
        for event in runner.run():
            etype = event.get("type", "")
            if etype == "action":
                last_action = Action(
                    tool=event["tool"], target=event["target"],
                    args={}, reasoning=event.get("reasoning", ""),
                    phase=event.get("phase", "recon"),
                )
                mission.iterations += 1
                mission.phase = event.get("phase", "recon")

            render(layout, mission, graph,
                   thinking=event.get("thinking", ""),
                   last_action=last_action,
                   last_result=last_result)

            if etype == "complete":
                time.sleep(1)
                break

    console.print("\n[bold green]✓ Demo complete![/bold green]")
    console.print(
        f"  Hosts: [green]{len(graph.hosts)}[/green]  "
        f"Findings: [yellow]{len(graph.findings)}[/yellow]"
    )
    if web_handle:
        web_handle.shutdown()


# ── Live mode ─────────────────────────────────────────────────────────────────

def run_live(args):
    api_key = (
        args.api_key
        or os.environ.get("ORACLE_API_KEY", "")
        or os.environ.get("ANTHROPIC_API_KEY", "")
    )

    mission = Mission(
        name=args.mission_name or f"mission_{int(time.time())}",
        scope=args.scope or [],
        objective=args.objective,
        profile=args.profile,
        max_iterations=args.max_iter,
    )

    graph, registry, ai, executor, safety = build_stack(mission, api_key, args=args)
    config_path = Path(args.config) if getattr(args, "config", None) else None
    preflight_rc = _run_startup_preflight(
        registry=registry,
        web_enabled=bool(args.web),
        web_auth_token=str(args.web_auth_token or ""),
        web_auth_user=str(args.web_auth_user or ""),
        web_auth_pass=str(args.web_auth_pass or ""),
        config_path=config_path,
    )
    if preflight_rc != 0:
        raise RuntimeError("startup preflight failed")
    runtime_mode = str(os.environ.get("ORACLE_RUNTIME_MODE", "live")).strip().lower()

    console.print(
        f"[green]Scope: {safety.scope_summary()}[/green]\n"
        f"[dim]{_advisor_status_line(ai)}[/dim]\n"
        f"[dim]Runtime mode: {runtime_mode}[/dim]\n"
        f"[dim]Build: {get_build_identity()['semantic_version']} ({get_build_identity()['git_hash']}) schema={get_build_identity()['schema_version']}[/dim]"
    )

    layout = make_layout()
    last_action, last_result, thinking = None, None, ""

    def approve_cb(action: Action) -> bool:
        """Interactive approval prompt (used in --copilot mode)."""
        console.print(f"\n[yellow]⚠ Approval needed: {action.tool} on {action.target}[/yellow]")
        console.print(f"  Args: {action.args}")
        console.print(f"  Reason: {action.reasoning[:100]}")
        return Confirm.ask("Execute?")

    audit = None
    if args.audit_log:
        if args.audit_log == "auto":
            ap = LOG_DIR / f"{mission.name}_audit.jsonl"
        else:
            ap = Path(args.audit_log)
        audit = AuditLogger(AuditConfig(path=ap))

    webhook = None
    if getattr(args, "webhook_url", ""):
        webhook = WebhookNotifier(
            WebhookConfig(
                url=str(args.webhook_url),
                timeout_s=float(getattr(args, "webhook_timeout", 3.0) or 3.0),
                queue_max=int(getattr(args, "webhook_queue_max", 128) or 128),
            )
        )

    jitter = getattr(args, "action_jitter", None)
    if isinstance(jitter, str) and "," in jitter:
        try:
            a, b = jitter.split(",", 1)
            jitter = [float(a.strip()), float(b.strip())]
        except Exception:
            jitter = None

    opsec = {
        "action_jitter": jitter,
        "network_throttle": bool(getattr(args, "network_throttle", False)),
        "copilot_mode": bool(getattr(args, "copilot", False)),
    }

    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=ai,
        executor=executor,
        safety=safety,
        approve_cb=approve_cb if args.copilot else None,
        audit=audit,
        webhook=webhook,
        opsec=opsec,
        runtime_mode=runtime_mode,
    )

    # Optional web dashboard
    web_handle = None
    if args.web:
        web_handle = _start_web(
            graph,
            mission,
            port=args.web_port,
            auth_token=(args.web_auth_token or ""),
            auth_user=(args.web_auth_user or ""),
            auth_pass=(args.web_auth_pass or ""),
            plugin_registry=registry,
            dispatcher=getattr(engine, "dispatcher", None),
            event_bus=getattr(engine, "event_bus", None),
            artifact_router=getattr(engine, "artifact_router", None),
        )
        if not (args.web_auth_token or (args.web_auth_user and args.web_auth_pass)):
            console.print("[yellow]Dashboard auth credentials not set; non-loopback clients are blocked by default.[/yellow]")

    with Live(layout, refresh_per_second=3, screen=True) as live:
        for event in engine.run():
            etype = event.get("type", "")

            if etype == "thinking":
                thinking = "⟳ AI is reasoning..."
            elif etype == "decision":
                thinking = event.get("thinking", "")
                last_action = event.get("action")
            elif etype == "result":
                last_result = graph.actions[-1] if graph.actions else None
            elif etype in ("stopped", "complete"):
                render(layout, mission, graph, thinking, last_action, last_result)
                time.sleep(1)
                break

            render(layout, mission, graph, thinking, last_action, last_result)

    console.print(
        f"\n[bold green]✓ Mission {mission.status}.[/bold green]  "
        f"Hosts: {len(graph.hosts)}  Findings: {len(graph.findings)}"
    )
    if web_handle:
        web_handle.shutdown()

    # Optional report
    if args.report or Confirm.ask("\n[cyan]Generate executive summary?[/cyan]"):
        _write_report(ai, graph, mission)


# ── Report helper ─────────────────────────────────────────────────────────────

def _write_report(ai, graph, mission):
    console.print("[dim]Generating report...[/dim]")
    if ai.ready:
        text = ai.summarize(graph)
        narrative = ai.tactical_narrative(graph) or ""
    else:
        text = graph.summary()
        narrative = ""
    path = LOG_DIR / f"{mission.name}_report.md"
    path.write_text(f"# ORACLE Report: {mission.name}\n\n{text}")
    console.print(f"[green]Report → {path}[/green]")
    console.print(Panel(text[:1500], title="Executive Summary", border_style="green"))

    # Deliverable HTML report (works even without AI key)
    gdict = graph.to_dict()
    if not narrative:
        narrative = deterministic_narrative(gdict, mission.name)
    html = render_html_report(graph_dict=gdict, mission_name=mission.name, narrative=narrative)
    hpath = LOG_DIR / f"{mission.name}_report.html"
    hpath.write_text(html)
    console.print(f"[green]HTML Report → {hpath}[/green]")


# ── Web dashboard ─────────────────────────────────────────────────────────────

def _start_web(
    graph,
    mission,
    port: int = 5000,
    *,
    auth_token: str = "",
    auth_user: str = "",
    auth_pass: str = "",
    plugin_registry=None,
    dispatcher=None,
    event_bus=None,
    artifact_router=None,
):
    try:
        from werkzeug.serving import make_server
        from web.backend_gateway import create_gateway

        app = create_gateway(
            mission=mission,
            graph=graph,
            dispatcher=dispatcher,
            plugin_registry=plugin_registry,
            event_bus=event_bus,
            artifact_router=artifact_router,
            auth_token=auth_token,
            auth_user=auth_user,
            auth_pass=auth_pass,
        )
        server = make_server("0.0.0.0", port, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        console.print(f"[green]🌐 Dashboard: http://0.0.0.0:{port}[/green]")
        return _WebHandle(server=server, thread=thread)
    except ImportError:
        from ..web.app import run_dashboard

        thread = threading.Thread(
            target=run_dashboard,
            args=(graph, mission, DATA_DIR),
            kwargs={
                "port": port,
                "auth_token": auth_token,
                "auth_user": auth_user,
                "auth_pass": auth_pass,
            },
            daemon=True,
        )
        thread.start()
        console.print(f"[green]🌐 Dashboard: http://0.0.0.0:{port}[/green]")
        return _WebHandle(thread=thread)


# ── Plugin list ───────────────────────────────────────────────────────────────

def list_plugins():
    reg = build_registry()
    table = Table(title="ORACLE Plugins", border_style="green")
    table.add_column("Name",      style="green")
    table.add_column("Category",  style="blue")
    table.add_column("Available", style="cyan")
    table.add_column("Description")
    for info in reg.info():
        table.add_row(
            info["name"], info["category"],
            "✓" if info["available"] else "✗",
            info["desc"],
        )
    console.print(table)


def list_missions():
    storage = Storage(DATA_DIR)
    keys = [key for key in storage.list_keys() if not key.endswith("__checkpoint")]
    table = Table(title="ORACLE Missions", border_style="green")
    table.add_column("Mission", style="green")
    table.add_column("Status", style="cyan")
    table.add_column("Phase", style="blue")
    table.add_column("Findings", style="yellow")
    table.add_column("Hosts", style="magenta")
    if not keys:
        table.add_row("(none)", "-", "-", "-", "-")
        console.print(table)
        return

    for key in sorted(keys):
        payload = storage.load(key) or {}
        findings = payload.get("findings", [])
        hosts = payload.get("hosts", {})
        status = str(payload.get("status", "unknown"))
        phase = str(payload.get("phase", "unknown"))
        table.add_row(
            key,
            status,
            phase,
            str(len(findings) if isinstance(findings, list) else 0),
            str(len(hosts) if isinstance(hosts, dict) else 0),
        )
    console.print(table)


def _build_version_string() -> str:
    identity = get_build_identity()
    commit = os.environ.get("ORACLE_BUILD_GIT", "").strip()
    build_date = os.environ.get("ORACLE_BUILD_DATE", "").strip()
    if not commit:
        try:
            root = Path(__file__).resolve().parents[2]
            proc = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=1.5,
                check=True,
            )
            commit = proc.stdout.strip()
        except Exception:
            commit = "unknown"
    if not build_date:
        build_date = time.strftime("%Y-%m-%d")
    return f"{VERSION_BASE} ({commit}, {build_date}) schema={identity['schema_version']}"


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oracle",
        description="ORACLE — Autonomous AI Red Team Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  oracle --demo                                      Run simulated demo
  oracle --scope 192.168.56.0/24                   Live mission
  oracle --scope 10.0.0.1 --copilot                Manual approval mode
  oracle --scope 10.0.0.1 --web --web-port 8080    With web dashboard
  oracle --list-plugins                             Show available plugins
        """
    )
    p.add_argument("--scope",         nargs="+",   metavar="TARGET")
    p.add_argument("--config",        metavar="PATH", help="Path to config.toml (default: ~/.oracle/config.toml)")
    p.add_argument("--mission-name",  metavar="NAME")
    p.add_argument("--objective",     default="Identify all reachable services and vulnerabilities")
    p.add_argument("--profile",       choices=["stealth","normal","aggressive"], default="normal")
    p.add_argument("--max-iter",      type=int,    default=30, metavar="N")
    p.add_argument("--api-key",       metavar="KEY")
    p.add_argument("--demo",          action="store_true")
    p.add_argument("--demo-speed",    type=float,  default=1.0, metavar="X")
    p.add_argument("--copilot",       action="store_true")
    p.add_argument("--report",        action="store_true")
    p.add_argument("--web",           action="store_true")
    p.add_argument("--web-port",      type=int,    default=5000, metavar="PORT")
    p.add_argument("--online-cve",    action="store_true", help="Enable online CVE enrichment (non-blocking)")
    p.add_argument("--nvd-api-key",   metavar="KEY", help="NVD API key (or set NVD_API_KEY)")
    p.add_argument("--vulners-api-key", metavar="KEY", help="Vulners API key (or set VULNERS_API_KEY)")
    p.add_argument("--web-auth-token", metavar="TOKEN", help="Require X-Oracle-Token for dashboard/API/SocketIO")
    p.add_argument("--web-auth-user", metavar="USER", help="Require HTTP basic auth (username)")
    p.add_argument("--web-auth-pass", metavar="PASS", help="Require HTTP basic auth (password)")
    p.add_argument("--audit-log", nargs="?", const="auto", metavar="PATH", help="Append-only audit log JSONL (default: ~/.oracle/logs/<mission>_audit.jsonl)")
    p.add_argument("--rollback", metavar="WHAT", help="Rollback mission graph to snapshot and exit (e.g., last)")
    p.add_argument("--action-jitter", metavar="LO,HI", help="OPSEC jitter seconds (e.g., 2,5) or set action_jitter in config.toml")
    p.add_argument("--network-throttle", action="store_true", help="Enable stealth pacing between actions")
    p.add_argument("--webhook-url", metavar="URL", help="Webhook URL for alerts (CRITICAL findings / approval required)")
    p.add_argument("--webhook-timeout", type=float, default=3.0, metavar="S", help="Webhook timeout seconds (default: 3)")
    p.add_argument("--webhook-queue-max", type=int, default=128, metavar="N", help="Webhook queue max (default: 128)")
    p.add_argument("--doctor",        action="store_true", help="Run environment diagnostics and exit")
    p.add_argument("--selftest",      action="store_true", help="Run integrated readiness self-test and exit")
    p.add_argument("--strict",        action="store_true", help="Use with --doctor to fail on optional checks")
    p.add_argument("--list-plugins",  action="store_true")
    p.add_argument("--list-missions", action="store_true", help="List known mission snapshots for rollback/replay")
    p.add_argument("--replay",        metavar="MISSION", help="Inspect replay artifacts for a mission and exit")
    p.add_argument("--replay-id",     metavar="ID", help="Replay artifact id or prefix to inspect with --replay")
    p.add_argument("--replay-file",   metavar="PATH", help="Inspect an explicit replay artifact file with --replay")
    p.add_argument("--list-replays",  action="store_true", help="List replay artifacts for the mission passed to --replay")
    p.add_argument("--replay-json",   action="store_true", help="Print the selected replay artifact as JSON")
    p.add_argument("--debug",         action="store_true")
    p.add_argument("--version",       action="version", version=_build_version_string())
    return p


# ── Main ──────────────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗
 ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝
 ██║   ██║██████╔╝███████║██║     ██║     █████╗
 ██║   ██║██╔══██╗██╔══██║██║     ██║     ██╔══╝
 ╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝
  Offensive Recon And Command Logic Engine  v3.2
"""


def main():
    # Lightweight subcommand support without breaking existing flag UX.
    if len(sys.argv) > 1 and sys.argv[1] == "cve-update":
        from .cve_update import run as _cve_update

        raise SystemExit(_cve_update(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        from .rollback import run as _rollback

        raise SystemExit(_rollback(sys.argv[2:], data_dir=DATA_DIR))
    if len(sys.argv) > 1 and sys.argv[1] == "export":
        raise SystemExit(run_export(sys.argv[2:], data_dir=DATA_DIR, log_dir=LOG_DIR))
    if len(sys.argv) > 1 and sys.argv[1] == "replay":
        raise SystemExit(run_replay(sys.argv[2:], data_dir=DATA_DIR))

    # Pre-parse to allow config defaults to populate argparse.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", metavar="PATH")
    known, _ = pre.parse_known_args()
    cfg_path = Path(known.config) if known.config else None
    cfg = load_config(cfg_path)

    parser = build_parser()
    parser.set_defaults(**argparse_defaults_from_config(cfg))
    args = parser.parse_args()

    level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(LOG_DIR / "oracle.log")],
    )

    console.print(f"[bold red]{BANNER}[/bold red]")

    try:
        if args.list_plugins:
            list_plugins()
        elif args.list_missions:
            list_missions()
        elif args.doctor:
            # Build minimal registry for checks
            reg = build_registry()
            raise SystemExit(
                run_doctor(
                    console,
                    registry=reg,
                    data_dir=DATA_DIR,
                    log_dir=LOG_DIR,
                    strict=bool(args.strict),
                    web_enabled=bool(args.web),
                    web_auth_token=str(args.web_auth_token or ""),
                    web_auth_user=str(args.web_auth_user or ""),
                    web_auth_pass=str(args.web_auth_pass or ""),
                )
            )
        elif args.selftest:
            reg = build_registry()
            raise SystemExit(
                run_selftest(
                    console,
                    registry=reg,
                    data_dir=DATA_DIR,
                    log_dir=LOG_DIR,
                )
            )
        elif args.replay:
            replay_argv = ["--mission", str(args.replay)]
            if args.list_replays:
                replay_argv.append("--list")
            if args.replay_json:
                replay_argv.append("--json")
            if args.replay_id:
                replay_argv.extend(["--replay-id", str(args.replay_id)])
            if args.replay_file:
                replay_argv.extend(["--artifact", str(args.replay_file)])
            raise SystemExit(run_replay(replay_argv, data_dir=DATA_DIR, console=console))
        elif args.rollback:
            from .rollback import run as _rollback

            if not args.mission_name:
                console.print("[red]--rollback requires --mission-name[/red]")
                raise SystemExit(1)
            raise SystemExit(_rollback(["--mission", args.mission_name, str(args.rollback)], data_dir=DATA_DIR))
        elif args.demo:
            run_demo(args)
        else:
            run_live(args)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red][✗] {e}[/red]")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
