from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, List, Dict

import requests
from rich.console import Console


def _validate_db(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, list):
        raise ValueError("DB must be a JSON list")
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            continue
        patterns = row.get("patterns")
        cves = row.get("cves")
        if not isinstance(patterns, list) or not isinstance(cves, list):
            continue
        if not all(isinstance(p, str) for p in patterns):
            continue
        if not all(isinstance(c, str) for c in cves):
            continue
        out.append(row)
    if not out:
        raise ValueError("No valid entries found (need rows with patterns[] and cves[])")
    return out


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run(argv: list[str]) -> int:
    c = Console()
    p = argparse.ArgumentParser(prog="oracle cve-update", description="Update offline CVE mapping database")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-url", metavar="URL", help="Download JSON mapping from URL")
    src.add_argument("--from-file", metavar="PATH", help="Load JSON mapping from local file")
    p.add_argument("--sha256", metavar="HEX", help="Verify downloaded content hash (recommended for --from-url)")
    p.add_argument("--insecure", action="store_true", help="Allow --from-url without --sha256")
    p.add_argument("--out", metavar="PATH", help="Output path (default: ~/.oracle/cve_offline.json)")
    args = p.parse_args(argv)

    out = Path(args.out) if args.out else (Path.home() / ".oracle" / "cve_offline.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    raw: bytes
    if args.from_file:
        raw = Path(args.from_file).read_bytes()
    else:
        if not args.sha256 and not args.insecure:
            c.print("[red]Refusing URL update without --sha256. Use --insecure to override.[/red]")
            return 1
        r = requests.get(args.from_url, timeout=20)
        if r.status_code != 200:
            c.print(f"[red]Download failed HTTP {r.status_code}[/red]")
            return 1
        raw = r.content
        if args.sha256:
            got = _sha256_bytes(raw)
            if got.lower() != args.sha256.lower():
                c.print(f"[red]SHA256 mismatch[/red]\nexpected: {args.sha256}\n   got: {got}")
                return 1

    data = json.loads(raw.decode("utf-8"))
    valid = _validate_db(data)
    out.write_text(json.dumps(valid, indent=2))
    c.print(f"[green]Offline CVE DB updated:[/green] {out}")
    c.print(f"[dim]Entries:[/dim] {len(valid)}")
    return 0

