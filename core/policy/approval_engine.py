"""Deterministic approval decisions."""

from __future__ import annotations

from oracle.core.models import Action

from .policy_engine import PolicyEngine
from .risk_classifier import RiskClassifier


class ApprovalEngine:
    """Determines whether an action requires human approval."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.risk = RiskClassifier(policy)

    def requires_approval(self, action: Action, confidence: float) -> bool:
        phase = action.phase
        if self.policy.approval_required(phase):
            return True
        if confidence < self.policy.approval_floor(phase):
            return True
        return self.risk.classify(action.tool) in {"high", "critical"}

