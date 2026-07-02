"""Simple risk classification for planner-selected actions."""

from __future__ import annotations

from .policy_engine import PolicyEngine


class RiskClassifier:
    """Maps tools to policy-defined risk levels."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def classify(self, tool: str) -> str:
        return self.policy.tool_risk(tool)

