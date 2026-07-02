"""Fallback action selection after retries are exhausted."""

from __future__ import annotations

from typing import Any, Dict

from oracle.core.models import Action

from core.orchestrator.job_tracker import JobTracker
from core.policy.policy_engine import PolicyEngine


class FallbackEngine:
    """Chooses deterministic fallback actions from policy."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def build_fallback(self, action: Action, tracker: JobTracker) -> Action | None:
        retries = self.policy.retry_policy(action.phase)
        max_attempts = int(retries.get("max_attempts", 0))
        if tracker.stats_for(action).failures <= max_attempts:
            return None
        for tool in self.policy.fallback_tools(action.phase, action.tool):
            candidate = self._fallback_for_tool(action, tool)
            if candidate and not tracker.has_success(candidate):
                return candidate
        return None

    def _fallback_for_tool(self, action: Action, tool: str) -> Action | None:
        args = self._build_args(action, tool)
        if args is None:
            return None
        return Action(
            tool=tool,
            target=action.target,
            args=args,
            confidence=self.policy.min_confidence(action.phase),
            reasoning=f"Policy fallback from {action.tool} to {tool}",
            phase=action.phase,
            timeout=int(args.pop("timeout", action.timeout)),
            expected=f"Fallback validation using {tool}",
        )

    def _build_args(self, action: Action, tool: str) -> Dict[str, Any] | None:
        defaults = self.policy.default_args(action.phase, tool)
        if tool == "http":
            port = int((action.args or {}).get("port", 80))
            return {
                "port": port,
                "path": defaults.get("path", "/"),
                "method": defaults.get("method", "GET"),
                "timeout": defaults.get("timeout", 20),
            }
        if tool == "fuzz":
            port = int((action.args or {}).get("port", 80))
            return {
                "port": port,
                "wordlist": defaults.get("wordlist", "common"),
                "extensions": defaults.get("extensions", "php,html,txt"),
                "threads": defaults.get("threads", 20),
                "timeout": defaults.get("timeout", 90),
            }
        if tool == "nmap":
            port = (action.args or {}).get("port")
            ports = str(port) if port else defaults.get("ports", "")
            return {
                "ports": ports,
                "timing": defaults.get("timing", "T3"),
                "timeout": defaults.get("timeout", 60),
            }
        return None

