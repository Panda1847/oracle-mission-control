from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from ..memory.storage import Storage


def run(argv: list[str], *, data_dir: Path) -> int:
    c = Console()
    p = argparse.ArgumentParser(prog="oracle rollback", description="Rollback mission graph to last snapshot")
    p.add_argument("--mission", required=True, help="Mission name (same as mission file stem)")
    p.add_argument("which", nargs="?", default="last", help="Snapshot to restore (default: last)")
    p.add_argument("--list", action="store_true", help="List available snapshots and exit")
    args = p.parse_args(argv)

    storage = Storage(data_dir)
    if args.list:
        snaps = storage.list_backups(args.mission)
        if not snaps:
            c.print("[yellow]No snapshots found.[/yellow]")
            return 0
        for s in snaps[:30]:
            c.print(str(s))
        return 0

    restored = storage.restore_backup(args.mission, which=args.which)
    if not restored:
        c.print("[red]No snapshot found to restore.[/red]")
        return 1
    c.print(f"[green]Restored snapshot:[/green] {restored}")
    return 0

