"""Canonical council round and review helpers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _action_from_payload(payload: Dict[str, Any] | None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    action = payload.get("action")
    if isinstance(action, dict):
        return {
            "tool": str(action.get("tool", "") or ""),
            "target": str(action.get("target", "") or ""),
            "args": dict(action.get("args", {}) or {}),
        }
    tool = str(payload.get("tool", "") or "")
    target = str(payload.get("target", "") or "")
    if tool or target:
        return {
            "tool": tool,
            "target": target,
            "args": dict(payload.get("args", {}) or {}),
        }
    return {}


def _role_breakdown(council: Dict[str, Any]) -> List[Dict[str, Any]]:
    roles = dict(council.get("roles", {}) or {})
    items: List[Dict[str, Any]] = []
    for role, payload in roles.items():
        entry = dict(payload or {})
        action = _action_from_payload(entry)
        items.append(
            {
                "role": str(role or ""),
                "tool": str(entry.get("tool", action.get("tool", "")) or ""),
                "target": str(entry.get("target", action.get("target", "")) or ""),
                "confidence": float(entry.get("confidence", 0.0) or 0.0),
                "reasoning": str(entry.get("reasoning", "") or ""),
                "expected": str(entry.get("expected", "") or ""),
                "stop_reason": str(entry.get("stop_reason", "") or ""),
                "agrees_with_arbiter": bool(entry.get("agrees_with_arbiter", False)),
            }
        )
    return sorted(items, key=lambda item: (item["role"] != "verifier", item["role"] != "proposer", item["role"]))


def build_council_round(
    recommendation: Dict[str, Any] | None,
    *,
    final_action: Dict[str, Any] | None = None,
    decision_source: str = "",
    gate_reason: str = "",
    phase: str = "",
    branch: str = "",
    created_at: str = "",
    trace_id: str = "",
    replay_id: str = "",
) -> Dict[str, Any]:
    recommendation = dict(recommendation or {})
    council = dict(recommendation.get("council", {}) or {})
    recommended_action = _action_from_payload(recommendation)
    final_action = _action_from_payload(final_action or {})
    if not council and not recommended_action:
        return {}
    consensus = dict(council.get("consensus", {}) or {})
    outcome = "accepted" if str(decision_source or "") == "advisor" else "fallback"
    return {
        "phase": str(phase or ""),
        "branch": str(branch or ""),
        "trace_id": str(trace_id or ""),
        "created_at": str(created_at or ""),
        "replay_id": str(replay_id or ""),
        "arbiter": str(council.get("arbiter", "") or ""),
        "recommended_tool": str(recommended_action.get("tool", "") or ""),
        "recommended_target": str(recommended_action.get("target", "") or ""),
        "recommendation_confidence": float(recommendation.get("confidence", 0.0) or 0.0),
        "recommendation_reasoning": str(recommendation.get("reasoning", "") or ""),
        "final_tool": str(final_action.get("tool", "") or ""),
        "final_target": str(final_action.get("target", "") or ""),
        "decision_source": str(decision_source or ""),
        "gate_reason": str(gate_reason or ""),
        "outcome": outcome,
        "override": bool(str(decision_source or "") and str(decision_source or "") != "advisor"),
        "agreement_count": int(consensus.get("agreement_count", 0) or 0),
        "eligible_votes": int(consensus.get("eligible_votes", 0) or 0),
        "is_unanimous": bool(consensus.get("is_unanimous", False)),
        "is_split_vote": bool(consensus.get("is_split_vote", False)),
        "role_breakdown": _role_breakdown(council),
    }


def extract_council_rounds_from_events(payloads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pending_by_trace: Dict[str, Dict[str, Any]] = {}
    pending_queue: List[Dict[str, Any]] = []
    rounds: List[Dict[str, Any]] = []
    for item in payloads:
        payload = dict(item or {})
        event_type = str(payload.get("type", "") or "")
        trace_id = str(payload.get("trace_id", "") or "")
        if event_type == "ai_decision_result" and isinstance(payload.get("council"), dict) and payload.get("council"):
            if trace_id:
                pending_by_trace[trace_id] = payload
            else:
                pending_queue.append(payload)
            continue
        if event_type != "decision":
            continue
        if not (isinstance(payload.get("council"), dict) and payload.get("council")):
            continue
        ai_payload: Dict[str, Any] = {}
        if trace_id and trace_id in pending_by_trace:
            ai_payload = pending_by_trace.pop(trace_id)
        elif pending_queue:
            ai_payload = pending_queue.pop(0)
        recommendation = {
            "tool": str(ai_payload.get("recommended_tool", "") or ""),
            "target": str(ai_payload.get("recommended_target", "") or ""),
            "confidence": float(ai_payload.get("recommendation_confidence", 0.0) or 0.0),
            "reasoning": str(ai_payload.get("recommendation_reasoning", "") or ""),
            "council": dict(ai_payload.get("council", {}) or payload.get("council", {}) or {}),
        }
        round_item = build_council_round(
            recommendation,
            final_action=dict(payload.get("action", {}) or {}),
            decision_source=str(payload.get("decision_source", "") or ""),
            gate_reason=str(payload.get("gate_reason", "") or ""),
            phase=str(payload.get("phase", ai_payload.get("phase", "")) or ""),
            created_at=str(payload.get("created_at", ai_payload.get("created_at", "")) or ""),
            trace_id=trace_id or str(ai_payload.get("trace_id", "") or ""),
        )
        if round_item:
            rounds.append(round_item)
    return rounds


def extract_council_rounds_from_replay_records(replay_records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rounds: List[Dict[str, Any]] = []
    for item in replay_records:
        replay = dict(item or {})
        round_item = dict(replay.get("council_round", {}) or {})
        if not round_item:
            round_item = build_council_round(
                dict(replay.get("validated_recommendation", {}) or replay.get("raw_ai_response", {}) or {}),
                final_action=dict(replay.get("action", {}) or {}),
                decision_source=str(replay.get("decision_source", "") or ""),
                gate_reason=str(replay.get("gate_reason", "") or ""),
                phase=str(replay.get("phase", "") or ""),
                branch=str(replay.get("branch", "") or ""),
                created_at=str(replay.get("created_at", "") or ""),
                replay_id=str(replay.get("replay_id", "") or ""),
            )
        if round_item:
            rounds.append(round_item)
    return rounds


def summarize_council_rounds(rounds: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    items = [dict(item or {}) for item in rounds if dict(item or {})]
    accepted_count = sum(1 for item in items if str(item.get("outcome", "")) == "accepted")
    fallback_count = sum(1 for item in items if str(item.get("outcome", "")) == "fallback")
    split_vote_count = sum(1 for item in items if bool(item.get("is_split_vote", False)))

    max_override_streak = 0
    current_override_streak = 0
    for item in items:
        if bool(item.get("override", False)):
            current_override_streak += 1
            max_override_streak = max(max_override_streak, current_override_streak)
        else:
            current_override_streak = 0
    trailing_override_streak = 0
    for item in reversed(items):
        if bool(item.get("override", False)):
            trailing_override_streak += 1
        else:
            break

    recommendation_drift_count = 0
    final_action_drift_count = 0
    arbiter_drift_count = 0
    last_drift: Dict[str, Any] = {}
    for previous, current in zip(items, items[1:]):
        previous_recommendation = f"{previous.get('recommended_tool', '')}|{previous.get('recommended_target', '')}"
        current_recommendation = f"{current.get('recommended_tool', '')}|{current.get('recommended_target', '')}"
        previous_final = f"{previous.get('final_tool', '')}|{previous.get('final_target', '')}"
        current_final = f"{current.get('final_tool', '')}|{current.get('final_target', '')}"
        if previous_recommendation and current_recommendation and previous_recommendation != current_recommendation:
            recommendation_drift_count += 1
            last_drift = {
                "kind": "recommendation",
                "from": previous_recommendation,
                "to": current_recommendation,
                "phase": str(current.get("phase", "") or ""),
            }
        if previous_final and current_final and previous_final != current_final:
            final_action_drift_count += 1
            last_drift = {
                "kind": "final_action",
                "from": previous_final,
                "to": current_final,
                "phase": str(current.get("phase", "") or ""),
            }
        if str(previous.get("arbiter", "") or "") and str(current.get("arbiter", "") or "") and previous.get("arbiter") != current.get("arbiter"):
            arbiter_drift_count += 1
            last_drift = {
                "kind": "arbiter",
                "from": str(previous.get("arbiter", "") or ""),
                "to": str(current.get("arbiter", "") or ""),
                "phase": str(current.get("phase", "") or ""),
            }

    alerts: List[str] = []
    if max_override_streak >= 2:
        alerts.append("repeated_overrides")
    if recommendation_drift_count >= 2:
        alerts.append("recommendation_drift")
    if split_vote_count >= 2:
        alerts.append("repeated_split_votes")

    return {
        "total_rounds": len(items),
        "accepted_count": accepted_count,
        "fallback_count": fallback_count,
        "override_rate": float(fallback_count / len(items)) if items else 0.0,
        "max_override_streak": max_override_streak,
        "current_override_streak": trailing_override_streak,
        "recommendation_drift_count": recommendation_drift_count,
        "final_action_drift_count": final_action_drift_count,
        "arbiter_drift_count": arbiter_drift_count,
        "split_vote_count": split_vote_count,
        "last_drift": last_drift,
        "alerts": alerts,
        "recent_overrides": [item for item in items if bool(item.get("override", False))][-5:],
    }
