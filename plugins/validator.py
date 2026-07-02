"""Manifest validation for enterprise plugins."""

from __future__ import annotations

from pathlib import Path


REQUIRED_MANIFEST_FIELDS = {
    "name",
    "version",
    "category",
    "capabilities",
    "required_binaries",
    "risk_level",
    "expected_artifacts",
    "parser_schema",
    "timeout",
    "retry_policy",
    "confidence_weight",
    "approval_required",
}


def validate_manifest(manifest: dict, plugin_dir: Path) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_MANIFEST_FIELDS - set(manifest))
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
    if not isinstance(manifest.get("capabilities", []), list):
        errors.append("capabilities must be a list")
    if not isinstance(manifest.get("required_binaries", []), list):
        errors.append("required_binaries must be a list")
    parser_schema = manifest.get("parser_schema")
    if parser_schema and not (plugin_dir / str(parser_schema)).exists():
        errors.append(f"parser schema not found: {parser_schema}")
    return errors

