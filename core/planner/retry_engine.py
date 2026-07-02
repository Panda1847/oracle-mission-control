"""Retry rules with timeout escalation."""

from __future__ import annotations

from dataclasses import replace

from oracle.core.models import Action

from core.orchestrator.job_tracker import JobTracker
from core.policy.policy_engine import PolicyEngine


class RetryEngine:
    """Determines whether and how an action should be retried."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def build_retry(self, action: Action, tracker: JobTracker) -> Action | None:
        stats = tracker.stats_for(action)
        phase_policy = self.policy.retry_policy(action.phase)
        max_attempts = int(phase_policy.get("max_attempts", 0))
        if stats.failures == 0 or stats.failures > max_attempts:
            return None
        multiplier = float(phase_policy.get("timeout_multiplier", 1.0))
        timeout = max(action.timeout, 1)
        escalated = int(timeout * (multiplier ** stats.failures))
        return replace(
            action,
            timeout=escalated,
            reasoning=f"{action.reasoning} Retry attempt {stats.failures}/{max_attempts}.",
        )

