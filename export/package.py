"""Mission deliverable packaging helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from core.ai.council_review import extract_council_rounds_from_replay_records, summarize_council_rounds
from oracle import get_build_identity


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _zip_info(name: str, when: datetime) -> ZipInfo:
    info = ZipInfo(filename=name, date_time=when.astimezone(timezone.utc).timetuple()[:6])
    info.compress_type = ZIP_DEFLATED
    return info


def _dump_json(payload: Any) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")


def _dump_jsonl(items: Iterable[Any]) -> bytes:
    lines = [json.dumps(item, sort_keys=True, ensure_ascii=True, default=str) for item in items]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _build_structured_export_entries(
    *,
    graph_snapshot: dict[str, Any],
    summary: dict[str, Any],
    evidence: dict[str, Any],
    intelligence_report: dict[str, Any],
    replay_records: Iterable[dict[str, Any]] = (),
    provenance_records: Iterable[dict[str, Any]] = (),
    pdf_report: bytes | None = None,
) -> list[tuple[str, bytes]]:
    replay_items = [dict(item) for item in replay_records]
    provenance_items = [dict(item) for item in provenance_records]
    council_rounds = extract_council_rounds_from_replay_records(replay_items)
    council_review = summarize_council_rounds(council_rounds)
    executive_summary = str(intelligence_report.get("executive_summary", "") or summary.get("executive_summary", "")).strip()
    remediation_lines = [str(line).strip() for line in list(intelligence_report.get("remediation_text", []) or []) if str(line).strip()]
    findings = list(intelligence_report.get("ranked_findings", []) or list(graph_snapshot.get("findings", []) or []))
    evidence_records = list(evidence.get("evidence_records", []) or [])
    topology = dict(graph_snapshot.get("topology", {}) or {})

    entries: list[tuple[str, bytes]] = [
        ("executive_summary.md", f"# Executive Summary\n\n{executive_summary}\n".encode("utf-8")),
        ("findings.json", _dump_json(findings)),
        ("evidence.jsonl", _dump_jsonl(evidence_records)),
        ("provenance.jsonl", _dump_jsonl(provenance_items)),
        ("topology.json", _dump_json(topology)),
        ("replay.jsonl", _dump_jsonl(replay_items)),
        ("council_rounds.json", _dump_json(council_rounds)),
        ("council_review.json", _dump_json(council_review)),
        (
            "remediation.md",
            ("# Remediation\n\n" + "\n".join(f"- {line}" for line in remediation_lines) + "\n").encode("utf-8"),
        ),
    ]
    if pdf_report:
        entries.append(("summary.pdf", pdf_report))
    for idx, item in enumerate(replay_items, start=1):
        replay_id = str(item.get("replay_id", "") or f"replay-{idx}")
        entries.append((f"_replay_artifacts/{idx:03d}-{replay_id[:12]}.json", _dump_json(item)))
    return entries


@dataclass(frozen=True)
class MissionPackage:
    payload: bytes
    manifest: dict[str, Any]
    files: list[str]


@dataclass(frozen=True)
class MissionExport:
    export_dir: Path
    files: list[Path]
    package_path: Path
    package_manifest: dict[str, Any]


def build_mission_package(
    mission_name: str,
    *,
    mission_snapshot: dict[str, Any],
    graph_snapshot: dict[str, Any],
    summary: dict[str, Any],
    evidence: dict[str, Any],
    intelligence_report: dict[str, Any],
    bundle: dict[str, Any],
    pdf_report: bytes | None = None,
    replay_artifacts: Iterable[str | Path] = (),
    replay_records: Iterable[dict[str, Any]] = (),
    provenance_records: Iterable[dict[str, Any]] = (),
) -> MissionPackage:
    generated_at = _ts()
    generated_dt = datetime.fromisoformat(generated_at)
    replay_paths = [Path(item) for item in replay_artifacts if Path(item).exists()]
    replay_items = [dict(item) for item in replay_records]
    if not replay_items and replay_paths:
        replay_items = [_load_json(path) for path in replay_paths]
    structured_entries = _build_structured_export_entries(
        graph_snapshot=graph_snapshot,
        summary=summary,
        evidence=evidence,
        intelligence_report=intelligence_report,
        replay_records=replay_items,
        provenance_records=provenance_records,
        pdf_report=pdf_report,
    )
    entries: list[tuple[str, bytes]] = [
        ("mission/snapshot.json", _dump_json(graph_snapshot)),
        ("reports/summary.json", _dump_json(summary)),
        ("reports/evidence.json", _dump_json(evidence)),
        ("reports/intelligence.json", _dump_json(intelligence_report)),
        ("reports/bundle.json", _dump_json(bundle)),
    ]
    if pdf_report:
        entries.append(("reports/summary.pdf", pdf_report))
    for path in sorted(replay_paths, key=lambda item: item.name):
        entries.append((f"replay/{path.name}", path.read_bytes()))
    entries.extend((f"exports/{name}", payload) for name, payload in structured_entries)

    manifest = {
        "schema_version": "oracle-package.v1",
        "mission": mission_name,
        "generated_at": generated_at,
        "build_identity": get_build_identity(),
        "mission_snapshot": mission_snapshot,
        "report_schema_version": intelligence_report.get("report_schema_version", ""),
        "counts": {
            "hosts": len(graph_snapshot.get("hosts", {}) or {}) if isinstance(graph_snapshot.get("hosts"), dict) else 0,
            "findings": len(graph_snapshot.get("findings", []) or []) if isinstance(graph_snapshot.get("findings"), list) else 0,
            "artifacts": len(entries) + 1,
            "replay_artifacts": len(replay_paths),
            "delivery_exports": len(structured_entries),
            "council_rounds": len(extract_council_rounds_from_replay_records(replay_items)),
        },
        "included_files": [name for name, _ in entries] + ["manifest.json"],
    }

    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as archive:
        for name, payload in entries:
            archive.writestr(_zip_info(name, generated_dt), payload)
        archive.writestr(_zip_info("manifest.json", generated_dt), _dump_json(manifest))
    return MissionPackage(
        payload=buffer.getvalue(),
        manifest=manifest,
        files=manifest["included_files"],
    )


def _write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_dump_json(payload))


def _write_bytes(path: Path, payload: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _write_jsonl(path: Path, items: Iterable[Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True, ensure_ascii=True, default=str) + "\n")


def build_mission_export(
    export_root: str | Path,
    mission_name: str,
    *,
    mission_snapshot: dict[str, Any],
    graph_snapshot: dict[str, Any],
    summary: dict[str, Any],
    evidence: dict[str, Any],
    intelligence_report: dict[str, Any],
    bundle: dict[str, Any],
    replay_records: Iterable[dict[str, Any]] = (),
    provenance_records: Iterable[dict[str, Any]] = (),
    pdf_report: bytes | None = None,
) -> MissionExport:
    export_dir = Path(export_root) / mission_name
    export_dir.mkdir(parents=True, exist_ok=True)
    replay_items = [dict(item) for item in replay_records]
    provenance_items = [dict(item) for item in provenance_records]
    structured_entries = _build_structured_export_entries(
        graph_snapshot=graph_snapshot,
        summary=summary,
        evidence=evidence,
        intelligence_report=intelligence_report,
        replay_records=replay_items,
        provenance_records=provenance_items,
        pdf_report=pdf_report,
    )
    replay_paths: list[Path] = []
    files: list[Path] = []
    for relative_name, payload in structured_entries:
        target = export_dir / relative_name
        _write_bytes(target, payload)
        files.append(target)
        if relative_name.startswith("_replay_artifacts/"):
            replay_paths.append(target)

    package = build_mission_package(
        mission_name,
        mission_snapshot=mission_snapshot,
        graph_snapshot=graph_snapshot,
        summary=summary,
        evidence=evidence,
        intelligence_report=intelligence_report,
        bundle=bundle,
        pdf_report=pdf_report,
        replay_artifacts=replay_paths,
        replay_records=replay_items,
        provenance_records=provenance_items,
    )
    package_path = export_dir / "package.zip"
    package_path.write_bytes(package.payload)
    files.append(package_path)
    return MissionExport(
        export_dir=export_dir,
        files=files,
        package_path=package_path,
        package_manifest=package.manifest,
    )
