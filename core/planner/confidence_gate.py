"""Confidence-based approval of advisory AI recommendations."""

from __future__ import annotations

from dataclasses import dataclass

from oracle.core.models import Action

from core.policy.policy_engine import PolicyEngine


@dataclass
class GateDecision:
    """Final action selection after confidence gating."""

    action: Action
    source: str
    confidence: float
    accepted: bool
    reason: str


class ConfidenceGate:
    """Allows AI to recommend only from planner-generated candidates."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def select(self, phase: str, candidates: list[Action], recommendation: dict | None) -> GateDecision:
        if not candidates:
            raise ValueError("ConfidenceGate.select requires at least one candidate action")

        threshold = self.policy.min_confidence(phase)
        if not recommendation:
            action = candidates[0]
            return GateDecision(action, "planner_default", action.confidence, False, "No advisor recommendation available.")

        confidence = float(recommendation.get("confidence", 0.0) or 0.0)
        tool = str(recommendation.get("tool", ""))
        target = str(recommendation.get("target", ""))

        matched = next((candidate for candidate in candidates if candidate.tool == tool and candidate.target == target), None)
        if matched is None:
            action = candidates[0]
            return GateDecision(action, "planner_default", action.confidence, False, "Advisor chose an action outside the deterministic candidate set.")

        if confidence < threshold:
            action = candidates[0]
            return GateDecision(action, "planner_default", action.confidence, False, f"Advisor confidence {confidence:.2f} is below required threshold {threshold:.2f}.")

        matched.reasoning = recommendation.get("reasoning", matched.reasoning)
        matched.confidence = confidence
        matched.expected = recommendation.get("expected", matched.expected)
        return GateDecision(matched, "advisor", confidence, True, "Advisor recommendation accepted by confidence gate.")

