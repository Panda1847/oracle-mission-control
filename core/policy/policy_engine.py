"""Loads and serves deterministic planner policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


class PolicyEngine:
    """Central policy loader backed by `config/policy.yaml`."""

    def __init__(self, policy_path: str | Path | None = None):
        root = Path(__file__).resolve().parents[2]
        self.policy_path = Path(policy_path or (root / "config" / "policy.yaml"))
        self._policy = self._load()

    def _load(self) -> Dict[str, Any]:
        data = yaml.safe_load(self.policy_path.read_text()) or {}
        if not isinstance(data, dict):
            raise ValueError("policy.yaml must parse into a dictionary")
        return data

    @property
    def raw(self) -> Dict[str, Any]:
        return self._policy

    def phase_policy(self, phase: str) -> Dict[str, Any]:
        phases = self._policy.get("phases", {})
        return phases.get(phase, {})

    def allowed_tools(self, phase: str) -> list[str]:
        return list(self.phase_policy(phase).get("allowed_tools", []))

    def min_confidence(self, phase: str) -> float:
        return float(self.phase_policy(phase).get("min_confidence", 1.0))

    def retry_policy(self, phase: str) -> Dict[str, Any]:
        return dict(self.phase_policy(phase).get("retries", {}))

    def checkpoint_policy(self, phase: str) -> Dict[str, Any]:
        return dict(self.phase_policy(phase).get("checkpoint", {}))

    def default_args(self, phase: str, tool: str) -> Dict[str, Any]:
        defaults = self.phase_policy(phase).get("defaults", {})
        tool_defaults = defaults.get(tool, {})
        return dict(tool_defaults if isinstance(tool_defaults, dict) else {})

    def fallback_tools(self, phase: str, tool: str) -> list[str]:
        fallbacks = self.phase_policy(phase).get("fallback_tools", {})
        return list(fallbacks.get(tool, []))

    def approval_required(self, phase: str) -> bool:
        return bool(self.phase_policy(phase).get("approval_required", False))

    def approval_floor(self, phase: str) -> float:
        return float(self.phase_policy(phase).get("approval_on_confidence_below", 0.0))

    def tool_risk(self, tool: str) -> str:
        return str(self._policy.get("risk", {}).get("tools", {}).get(tool, "medium"))

