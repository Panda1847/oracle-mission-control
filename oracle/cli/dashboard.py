"""
ORACLE — Terminal Dashboard  (cli/dashboard.py)
Rich-based live terminal UI updated from engine events.
"""
from __future__ import annotations
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from ..core.models import Mission, Action, ActionResult
from ..memory.graph import KnowledgeGraph

console = Console()


def make_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=3),
        Layout(name="stats",   size=3),
        Layout(name="body",    ratio=1),
        Layout(name="footer",  size=3),
    )
    layout["body"].split_row(
        Layout(name="left",  ratio=2),
        Layout(name="right", ratio=3),
    )
    layout["right"].split_column(
        Layout(name="graph",   ratio=2),
        Layout(name="actions", ratio=1),
    )
    return layout


def render(layout: Layout, mission: Mission, graph: KnowledgeGraph,
           thinking: str = "",
           last_action: Optional[Action] = None,
           last_result: Optional[ActionResult] = None):
    """Redraw every panel of the terminal dashboard."""

    # ── Header ────────────────────────────────────────────────────────────────
    status_color = "green" if mission.status == "running" else "red"
    layout["header"].update(Panel(
        Text(
            f"⚡ ORACLE  │  Mission: {mission.name}  │  "
            f"Phase: {mission.phase.upper()}  │  "
            f"Profile: {mission.profile}  │  "
            f"Iter: {mission.iterations}/{mission.max_iterations}",
            justify="center", style="bold blue"
        ),
        border_style=status_color,
    ))

    # ── Stats ─────────────────────────────────────────────────────────────────
    stats = graph.to_dict().get("stats", {})
    st = Text(justify="center")
    st.append(f"  HOSTS: {stats.get('hosts',0)}  ",    style="bold green")
    st.append(f"│  FINDINGS: {stats.get('findings',0)}  ", style="bold white")
    st.append(f"│  CRITICAL: {stats.get('critical',0)}  ", style="bold red")
    st.append(f"│  HIGH: {stats.get('high',0)}  ",      style="bold yellow")
    layout["stats"].update(Panel(st, border_style="dim"))

    # ── Left: thinking + last action ─────────────────────────────────────────
    left = Text()
    left.append("🧠 AI THINKING:\n", style="bold yellow")
    left.append((thinking[:300] if thinking else "Awaiting decision...") + "\n\n")

    if last_action:
        left.append("⚡ LAST ACTION:\n", style="bold cyan")
        left.append(f"  Tool:    {last_action.tool}\n", style="green")
        left.append(f"  Target:  {last_action.target}\n", style="blue")
        left.append(f"  Reason:  {last_action.reasoning[:90]}\n")
        left.append(f"  Args:    {str(last_action.args)[:80]}\n", style="dim")

    if last_result:
        ok_style = "green" if last_result.success else "red"
        left.append(
            f"\n  rc={last_result.returncode}  {last_result.duration:.1f}s\n",
            style=ok_style
        )
        if not last_result.success and last_result.stderr:
            left.append(f"  ERR: {last_result.stderr[:100]}\n", style="red")

    if graph.recent_directives():
        left.append("\n📋 OPERATOR DIRECTIVES:\n", style="bold magenta")
        for d in graph.recent_directives():
            left.append(f"  ▶ {d[:80]}\n", style="magenta")

    layout["left"].update(Panel(
        left,
        title="[bold yellow]Intel / Operator[/bold yellow]",
        border_style="yellow"
    ))

    # ── Right top: Knowledge graph ────────────────────────────────────────────
    layout["graph"].update(Panel(
        Text(graph.summary()),
        title="[bold green]Knowledge Graph[/bold green]",
        border_style="green"
    ))

    # ── Right bottom: Recent actions ──────────────────────────────────────────
    act_text = Text()
    recent = [a for a in graph.actions[-6:] if isinstance(a, ActionResult)]
    for r in reversed(recent):
        c = "green" if r.success else "red"
        act_text.append(
            f"  {r.ts}  {r.action.tool:<10} {r.action.target:<20} "
            f"rc={r.returncode} {r.duration:.1f}s\n",
            style=c
        )
    layout["actions"].update(Panel(
        act_text or Text("No actions yet", style="dim"),
        title="[bold cyan]Action Feed[/bold cyan]",
        border_style="cyan"
    ))

    # ── Footer ────────────────────────────────────────────────────────────────
    layout["footer"].update(Panel(
        Text(
            f"  Scope: {', '.join(mission.scope)}  │  "
            f"Status: {mission.status.upper()}  │  "
            f"[Ctrl+C] to pause  │  Use --copilot for approval mode",
            justify="center", style="dim"
        ),
        border_style="dim"
    ))
