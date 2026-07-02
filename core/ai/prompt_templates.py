"""Prompt helpers for the advisory AI layer."""

from __future__ import annotations

from oracle.core.models import Action

PROMPT_VERSION = "2026-04-26.enterprise.v1"


def build_advisor_context(
    phase: str,
    candidates: list[Action],
    checkpoint_reason: str,
    *,
    advisor_state: dict | None = None,
) -> str:
    advisor_state = advisor_state or {}
    lines = [
        f"DETERMINISTIC PLANNER CONTEXT (prompt_version={PROMPT_VERSION})",
        f"CURRENT PHASE: {phase}",
        f"CHECKPOINT STATUS: {checkpoint_reason}",
        f"PHASE METRICS: {advisor_state.get('phase_completion_metrics', {})}",
        f"RECENT ACTIONS (last 5): {advisor_state.get('recent_actions', [])}",
        f"FAILED ACTIONS (recent): {advisor_state.get('failed_actions', [])}",
        f"EVIDENCE CONFIDENCE CLUSTERS: {advisor_state.get('evidence_confidence_clusters', {})}",
        f"CONTRADICTIONS: {advisor_state.get('contradictions', 0)}",
        f"UNTOUCHED HOSTS: {advisor_state.get('untouched_hosts', [])}",
        f"ATTACK GRAPH SUMMARY: {advisor_state.get('attack_graph_summary', {})}",
        "ALLOWED ACTIONS:",
    ]
    for idx, candidate in enumerate(candidates, start=1):
        lines.append(
            f"  {idx}. tool={candidate.tool} target={candidate.target} confidence={candidate.confidence} args={candidate.args} expected={candidate.expected}"
        )
    lines.append("Recommend only one of the listed actions. You are not the final authority.")
    lines.append("Return a single recommendation with rationale, expected outcome, and calibrated confidence.")
    return "\n".join(lines)
