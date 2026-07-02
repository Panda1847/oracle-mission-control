"""Contradiction detection for evidence observations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph_store import EvidenceRecord


class ContradictionDetector:
    """Flags conflicting evidence for the same logical entity."""

    def detect(self, existing: "EvidenceRecord" | None, incoming: "EvidenceRecord") -> str:
        if existing is None:
            return ""
        if existing.entity != incoming.entity or existing.value != incoming.value:
            return ""
        old_state = str(existing.payload.get("state") or existing.payload.get("status") or "").strip().lower()
        new_state = str(incoming.payload.get("state") or incoming.payload.get("status") or "").strip().lower()
        if old_state and new_state and old_state != new_state:
            return f"state changed from {old_state} to {new_state}"

        old_service = str(existing.payload.get("service", "")).strip().lower()
        new_service = str(incoming.payload.get("service", "")).strip().lower()
        if old_service and new_service and old_service != new_service:
            return f"service changed from {old_service} to {new_service}"

        old_version = str(existing.payload.get("version", "")).strip()
        new_version = str(incoming.payload.get("version", "")).strip()
        if old_version and new_version and old_version != new_version:
            return f"version changed from {old_version} to {new_version}"

        old_title = str(existing.payload.get("title", "")).strip()
        new_title = str(incoming.payload.get("title", "")).strip()
        if old_title and new_title and old_title != new_title:
            return f"title changed from {old_title} to {new_title}"

        old_sev = str(existing.payload.get("severity", "")).strip().upper()
        new_sev = str(incoming.payload.get("severity", "")).strip().upper()
        if old_sev and new_sev and old_sev != new_sev:
            return f"severity changed from {old_sev} to {new_sev}"

        old_cves = {str(c).upper() for c in (existing.payload.get("cves") or []) if str(c).strip()}
        new_cves = {str(c).upper() for c in (incoming.payload.get("cves") or []) if str(c).strip()}
        if old_cves and new_cves and old_cves != new_cves:
            if old_cves.isdisjoint(new_cves):
                return "cve set changed with no overlap"
            return "cve set changed"

        return ""
