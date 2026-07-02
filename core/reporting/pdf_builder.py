"""Minimal PDF generation for mission summary artifacts."""

from __future__ import annotations

from typing import Dict, List


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf_report(summary: Dict[str, object]) -> bytes:
    lines: List[str] = []
    lines.append(f"ORACLE Mission Report: {summary.get('mission', 'mission')}")
    stats = summary.get("stats", {}) or {}
    lines.append(f"Hosts: {stats.get('hosts', 0)}  Findings: {stats.get('findings', 0)}")
    lines.append("")
    for raw_line in str(summary.get("executive_summary", "")).splitlines():
        lines.append(raw_line)

    content_lines = ["BT", "/F1 12 Tf", "50 780 Td"]
    for index, line in enumerate(lines[:40]):
        if index:
            content_lines.append("0 -16 Td")
        content_lines.append(f"({_escape(line)}) Tj")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", "replace")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
        b"4 0 obj << /Length %d >> stream\n%s\nendstream endobj" % (len(content), content),
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
        pdf.extend(b"\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer << /Root 1 0 R /Size {len(objects) + 1} >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii")
    )
    return bytes(pdf)
