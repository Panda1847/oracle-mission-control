from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from memory.replay import ReplayStore


def _count_hosts(graph: dict[str, Any]) -> int:
    hosts = graph.get("hosts", {})
    return len(hosts) if isinstance(hosts, dict) else 0


def _count_findings(graph: dict[str, Any]) -> int:
    findings = graph.get("findings", [])
    if isinstance(findings, list):
        return len(findings)
    evidence = graph.get("evidence", [])
    return len(evidence) if isinstance(evidence, list) else 0


def _render_list(console: Console, store: ReplayStore, mission: str, limit: int) -> int:
    paths = store.list(mission)
    table = Table(title=f"ORACLE Replay Artifacts: {mission}", border_style="green")
    table.add_column("Replay ID", style="cyan")
    table.add_column("Phase", style="blue")
    table.add_column("Branch", style="magenta")
    table.add_column("Hosts", style="yellow")
    table.add_column("Findings", style="yellow")
    table.add_column("Artifact")
    if not paths:
        table.add_row("(none)", "-", "-", "-", "-", "-")
        console.print(table)
        return 0

    for path in reversed(paths[-max(1, int(limit)):]):
        artifact = store.load(path)
        graph_after = artifact.get("graph_snapshot_after", {})
        replay_id = str(artifact.get("replay_id", "") or "")[:12] or "(missing)"
        phase = str(artifact.get("phase", "") or "unknown")
        branch = str(artifact.get("branch", "") or "unknown")
        table.add_row(
            replay_id,
            phase,
            branch,
            str(_count_hosts(graph_after)),
            str(_count_findings(graph_after)),
            str(path),
        )
    console.print(table)
    return 0


def _render_summary(console: Console, artifact: dict[str, Any], *, path: Path) -> int:
    graph_before = artifact.get("graph_snapshot_before", {})
    graph_after = artifact.get("graph_snapshot_after", {})
    action = artifact.get("action", {}) if isinstance(artifact.get("action"), dict) else {}
    result = artifact.get("result", {}) if isinstance(artifact.get("result"), dict) else {}
    planner = artifact.get("planner_extra", {}) if isinstance(artifact.get("planner_extra"), dict) else {}

    table = Table(title="ORACLE Replay Summary", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("artifact", str(path))
    table.add_row("mission", str(artifact.get("mission", "") or ""))
    table.add_row("replay_id", str(artifact.get("replay_id", "") or ""))
    table.add_row("phase", str(artifact.get("phase", "") or ""))
    table.add_row("branch", str(artifact.get("branch", "") or ""))
    table.add_row("decision_source", str(artifact.get("decision_source", "") or ""))
    table.add_row("ai_backend", str(artifact.get("ai_backend", "") or ""))
    table.add_row("tool", str(action.get("tool", "") or ""))
    table.add_row("target", str(action.get("target", "") or ""))
    table.add_row("result.success", str(bool(result.get("success", False))))
    table.add_row("result.exit_code", str(result.get("exit_code", "")))
    table.add_row("findings.delta", str(len(artifact.get("ingest_delta", []) or [])))
    table.add_row("hosts.before", str(_count_hosts(graph_before)))
    table.add_row("hosts.after", str(_count_hosts(graph_after)))
    table.add_row("findings.before", str(_count_findings(graph_before)))
    table.add_row("findings.after", str(_count_findings(graph_after)))
    table.add_row("planner.phase", str(planner.get("phase", "") or ""))
    table.add_row("state_hash", str(artifact.get("state_hash", "") or ""))
    table.add_row("audit_hash", str(artifact.get("audit_hash", "") or ""))
    console.print(table)
    return 0


def run(argv: list[str], *, data_dir: Path, console: Console | None = None) -> int:
    console = console or Console()
    p = argparse.ArgumentParser(prog="oracle replay", description="Inspect mission replay artifacts")
    p.add_argument("--mission", required=True, help="Mission name (same as mission file stem)")
    p.add_argument("--list", action="store_true", help="List replay artifacts and exit")
    p.add_argument("--json", action="store_true", help="Print the selected replay artifact as JSON")
    p.add_argument("--limit", type=int, default=10, metavar="N", help="Number of artifacts to show with --list")
    p.add_argument("--replay-id", metavar="ID", help="Replay id or prefix to inspect")
    p.add_argument("--artifact", metavar="PATH", help="Inspect an explicit replay artifact path")
    args = p.parse_args(argv)

    store = ReplayStore(data_dir / "replay")
    if args.list:
        return _render_list(console, store, args.mission, max(1, int(args.limit)))

    if args.artifact:
        path = Path(args.artifact)
        if not path.exists():
            console.print(f"[red]Replay artifact not found:[/red] {path}")
            return 1
    else:
        path = store.find(args.mission, str(args.replay_id or ""))
        if path is None:
            console.print(f"[red]No replay artifacts found for mission:[/red] {args.mission}")
            return 1

    artifact = store.load(path)
    if args.json:
        console.print(json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True, default=str))
        return 0
    return _render_summary(console, artifact, path=path)
