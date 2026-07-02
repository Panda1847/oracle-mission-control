"""Validation for advisory AI recommendations."""

from __future__ import annotations

from typing import Any, Dict


class RecommendationValidator:
    """Normalizes best-effort advisor output into a narrow recommendation schema."""

    def validate(self, data: Dict[str, Any], candidates: list | None = None) -> Dict[str, Any] | None:
        if not isinstance(data, dict):
            return None
        if data.get("stop_reason"):
            return None
        action = data.get("action", {})
        if not isinstance(action, dict):
            return None
        tool = action.get("tool")
        target = action.get("target")
        if not tool or not target:
            return None
        if candidates:
            allowed = {(candidate.tool, candidate.target) for candidate in candidates}
            if (str(tool), str(target)) not in allowed:
                return None
        validated = {
            "tool": str(tool),
            "target": str(target),
            "reasoning": str(data.get("reasoning", "")),
            "expected": str(data.get("expected", "")),
            "confidence": float(data.get("confidence", 0.0) or 0.0),
            "prompt_version": str(data.get("prompt_version", "")),
        }
        if isinstance(data.get("council"), dict):
            validated["council"] = dict(data.get("council") or {})
        return validated
