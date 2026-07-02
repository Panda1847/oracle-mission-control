from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console

from core.reporting import build_evidence_export, build_intelligence_report, build_json_export, build_mission_summary, build_pdf_report
from export.package import build_mission_export
from memory.replay import ReplayStore
from oracle import get_build_identity

from ..memory.storage import Storage


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            loaded = json.loads(line)
        except Exception:
            continue
        if isinstance(loaded, dict):
            items.append(loaded)
    return items


def run(argv: list[str], *, data_dir: Path, log_dir: Path) -> int:
    c = Console()
    p = argparse.ArgumentParser(prog="oracle export", description="Generate structured mission exports")
    p.add_argument("--mission", required=True, help="Mission name (same as mission file stem)")
    p.add_argument("--output-dir", metavar="PATH", help="Override exports root directory")
    args = p.parse_args(argv)

    storage = Storage(data_dir)
    graph_dict = storage.load(args.mission)
    if not graph_dict:
        c.print(f"[red]Mission not found:[/red] {args.mission}")
        return 1

    mission_snapshot = {
        "phase": str(graph_dict.get("phase", "") or ""),
        "status": str(graph_dict.get("status", "") or ""),
        "build_identity": get_build_identity(),
    }
    summary = build_mission_summary(args.mission, graph_dict)
    evidence = build_evidence_export(graph_dict)
    intelligence = build_intelligence_report(args.mission, graph_dict, mission_snapshot=mission_snapshot)
    bundle = build_json_export(
        args.mission,
        summary,
        evidence,
        mission_snapshot=mission_snapshot,
        intelligence_report=intelligence,
    )
    pdf_report = build_pdf_report(summary)
    replay_store = ReplayStore(data_dir / "replay")
    replay_records = [replay_store.load(path) for path in replay_store.list(args.mission)]
    provenance = _read_jsonl(log_dir / f"{args.mission}_audit.jsonl")
    export_root = Path(args.output_dir) if args.output_dir else data_dir / "exports"
    exported = build_mission_export(
        export_root,
        args.mission,
        mission_snapshot=mission_snapshot,
        graph_snapshot=graph_dict,
        summary=summary,
        evidence=evidence,
        intelligence_report=intelligence,
        bundle=bundle,
        replay_records=replay_records,
        provenance_records=provenance,
        pdf_report=pdf_report,
    )
    c.print(f"[green]Export written:[/green] {exported.export_dir}")
    return 0
