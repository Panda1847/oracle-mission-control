"""Canonical dashboard live-stream serialization."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List


def _normalize_value(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    if hasattr(value, "__dict__") and not isinstance(value, (str, bytes, int, float, bool)):
        return {str(key): _normalize_value(item) for key, item in vars(value).items()}
    return value


def _action_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    action = payload.get("action")
    if isinstance(action, dict):
        return action
    return payload


def _channel_for_event(topic: str, payload: Dict[str, Any]) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if event_type in {"thinking"}:
        return "thinking"
    if event_type in {"decision", "action_complete", "phase_up", "approval_required", "approval_blocked", "denied", "strategy_reflection", "next_iteration_feedback", "ai_decision_start", "ai_decision_result"}:
        return "decision"
    if event_type in {"finding"}:
        return "finding"
    if event_type in {"graph_ingest", "attack_path_generated", "phase_internal", "report_generated", "checkpoint"}:
        return "graph_change"
    if event_type in {"parse_ok", "parse_quarantined", "evidence_pruned", "plugin_unavailable"}:
        return "evidence"
    return "system"


def _headline(topic: str, payload: Dict[str, Any], channel: str) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if channel == "thinking":
        return f"Iteration {int(payload.get('iteration', 0) or 0)} reasoning"
    if event_type == "decision":
        action = _action_payload(payload)
        tool = str(action.get("tool", "") or "?")
        target = str(action.get("target", "") or "?")
        return f"Decision: {tool} -> {target}"
    if event_type == "ai_decision_start":
        return "AI decision evaluation started"
    if event_type == "ai_decision_result":
        return "AI decision evaluation completed"
    if event_type == "action_complete":
        tool = str(payload.get("tool", "") or "?")
        target = str(payload.get("target", "") or "?")
        return f"Action: {tool} -> {target}"
    if event_type == "phase_up":
        return f"Phase transition -> {payload.get('phase', '')}"
    if event_type == "attack_path_generated":
        return "Attack path generated"
    if event_type == "graph_ingest":
        return "Graph ingested action result"
    if event_type == "finding":
        finding = _normalize_value(payload.get("finding", {}))
        return f"Finding: {finding.get('title', 'untitled')}"
    if event_type == "report_generated":
        return f"Report artifact: {payload.get('kind', 'artifact')}"
    if event_type == "parse_quarantined":
        return f"Parse quarantined: {payload.get('tool', '?')}"
    if event_type == "plugin_unavailable":
        return f"Plugin unavailable: {payload.get('tool', '?')}"
    if event_type == "evidence_pruned":
        return "Evidence pruned"
    return event_type.replace("_", " ").title()


def _summary(topic: str, payload: Dict[str, Any], channel: str) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if channel == "thinking":
        return "Planner and mission manager are evaluating the next action."
    if event_type == "phase_up":
        return str(payload.get("reason", "") or "phase advanced")
    if event_type == "attack_path_generated":
        score = float(payload.get("score", 0.0) or 0.0)
        path = " -> ".join(list(payload.get("path", []) or [])[:4])
        return f"{path} (score {score:.2f})".strip()
    if event_type == "graph_ingest":
        return f"{int(payload.get('findings', 0) or 0)} findings, {int(payload.get('hosts', 0) or 0)} hosts after ingest"
    if event_type == "finding":
        finding = _normalize_value(payload.get("finding", {}))
        severity = str(finding.get("severity", "INFO") or "INFO")
        host = str(finding.get("host", "") or "")
        port = int(finding.get("port", 0) or 0)
        return f"{severity} on {host}:{port}" if host else severity
    if event_type == "report_generated":
        return str(payload.get("artifact", "") or payload.get("kind", "artifact"))
    if event_type == "parse_quarantined":
        return str(payload.get("reason", "") or "parse contract validation failed")
    if event_type == "plugin_unavailable":
        return str(payload.get("reason", "") or "plugin unavailable")
    if event_type == "evidence_pruned":
        return f"Removed {int(payload.get('removed', 0) or 0)} expired evidence record(s)"
    if event_type == "approval_required":
        return f"{payload.get('tool', '?')} on {payload.get('target', '?')} requires approval"
    if event_type == "approval_ok":
        return f"{payload.get('tool', '?')} on {payload.get('target', '?')} approved"
    if event_type == "approval_denied":
        return f"{payload.get('tool', '?')} on {payload.get('target', '?')} denied"
    if event_type == "approval_blocked":
        return str(payload.get("reason", "") or "approval callback unavailable")
    if event_type == "decision":
        action = _action_payload(payload)
        return str(payload.get("reasoning", "") or action.get("reasoning", "") or payload.get("gate_reason", "") or "deterministic decision selected")
    if event_type == "ai_decision_start":
        graph_summary = dict(payload.get("attack_graph_summary", {}) or {})
        return f"{int(payload.get('candidate_count', 0) or 0)} candidates; graph paths {int(graph_summary.get('candidate_count', 0) or 0)}"
    if event_type == "ai_decision_result":
        arbiter = str(payload.get("council_arbiter", "") or "")
        backend = str(payload.get("backend", "") or "")
        council = dict(payload.get("council", {}) or {})
        consensus = dict(council.get("consensus", {}) or {})
        if arbiter:
            if consensus:
                agreement_count = int(consensus.get("agreement_count", 0) or 0)
                eligible_votes = int(consensus.get("eligible_votes", 0) or 0)
                return f"backend={backend or 'unknown'} arbiter={arbiter} agreement={agreement_count}/{eligible_votes}"
            return f"backend={backend or 'unknown'} arbiter={arbiter}"
        return f"backend={backend or 'unknown'} recommendation={'yes' if payload.get('has_recommendation') else 'no'}"
    if event_type == "checkpoint":
        return f"Replay branch {payload.get('branch', '')}"
    return str(payload.get("reason", "") or payload.get("status", "") or "")


def _priority(topic: str, payload: Dict[str, Any], channel: str) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if event_type in {"approval_required", "approval_blocked", "approval_denied"}:
        return "high"
    if event_type in {"parse_quarantined", "plugin_unavailable"}:
        return "high"
    if event_type == "finding":
        finding = _normalize_value(payload.get("finding", {}))
        severity = str(finding.get("severity", "INFO") or "INFO").upper()
        if severity in {"CRITICAL", "HIGH"}:
            return "high"
        if severity == "MEDIUM":
            return "medium"
    if event_type in {"attack_path_generated", "graph_ingest", "decision", "ai_decision_result"}:
        return "medium"
    if channel == "thinking":
        return "low"
    return "info"


def _operator_action(topic: str, payload: Dict[str, Any], channel: str) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if event_type == "approval_required":
        return "Review and approve or deny the queued action."
    if event_type == "approval_blocked":
        return "Configure an approval callback or switch to manual approval handling."
    if event_type == "approval_denied":
        return "Review the denial reason and choose a safer alternate action."
    if event_type == "plugin_unavailable":
        return "Verify plugin binaries or route to an alternate tool."
    if event_type == "parse_quarantined":
        return "Inspect parser output and quarantine handling before retrying."
    if event_type == "graph_ingest" and int(payload.get("findings", 0) or 0) > 0:
        return "Review the new evidence and decide whether to pivot or continue enumeration."
    if event_type == "attack_path_generated":
        return "Review the correlated path and validate whether it justifies exploit analysis."
    if event_type == "ai_decision_result" and str(payload.get("council_arbiter", "") or ""):
        return "Check whether the council arbiter aligns with operator intent before continuing."
    if event_type == "decision":
        source = str(payload.get("decision_source", "") or "")
        if source != "advisor" and str((payload.get("council", {}) or {}).get("arbiter", "") or ""):
            return "Review why the confidence gate overrode the council recommendation before continuing."
        if source == "advisor":
            return "Confirm the accepted advisor decision still fits the mission scope."
        return "Planner fallback selected the safest deterministic action."
    return ""


def _narrative(topic: str, payload: Dict[str, Any], channel: str) -> str:
    event_type = str(payload.get("type", topic) or topic)
    if channel == "thinking":
        phase = str(payload.get("phase", "") or "")
        return f"ORACLE is evaluating the next move in {phase or 'the current'} phase against deterministic guardrails."
    if event_type == "ai_decision_start":
        summary = dict(payload.get("attack_graph_summary", {}) or {})
        return (
            f"The advisor is reviewing {int(payload.get('candidate_count', 0) or 0)} allowed actions with "
            f"{int(summary.get('candidate_count', 0) or 0)} correlated path candidates in the canonical attack graph."
        )
    if event_type == "ai_decision_result":
        backend = str(payload.get("backend", "") or "unknown")
        arbiter = str(payload.get("council_arbiter", "") or "")
        tool = str(payload.get("recommended_tool", "") or "")
        target = str(payload.get("recommended_target", "") or "")
        council = dict(payload.get("council", {}) or {})
        consensus = dict(council.get("consensus", {}) or {})
        if arbiter:
            agreement_count = int(consensus.get("agreement_count", 0) or 0)
            eligible_votes = int(consensus.get("eligible_votes", 0) or 0)
            if agreement_count and eligible_votes:
                mode = "unanimous" if bool(consensus.get("is_unanimous", False)) else "split"
                return (
                    f"Council backend {backend} completed {mode} arbitration through {arbiter} and proposed "
                    f"{tool or 'no tool'} -> {target or 'no target'} with agreement {agreement_count}/{eligible_votes}."
                )
            return f"Council backend {backend} completed arbitration through {arbiter} and proposed {tool or 'no tool'} -> {target or 'no target'}."
        return f"Advisor backend {backend} returned {'a recommendation' if payload.get('has_recommendation') else 'no recommendation'}."
    if event_type == "decision":
        action = _action_payload(payload)
        source = str(payload.get("decision_source", "") or "")
        arbiter = str((payload.get("council", {}) or {}).get("arbiter", "") or "")
        if arbiter:
            if source == "advisor":
                return f"The confidence gate accepted the council-backed action {action.get('tool', '?')} -> {action.get('target', '?')} using arbiter={arbiter}."
            return (
                f"The confidence gate overrode the council recommendation and selected "
                f"{action.get('tool', '?')} -> {action.get('target', '?')} because {payload.get('gate_reason', 'planner fallback was safer')}."
            )
        return f"The confidence gate selected {action.get('tool', '?')} -> {action.get('target', '?')} using source={source}."
    if event_type == "attack_path_generated":
        node_ids = list(payload.get("node_ids", []) or [])
        return f"Correlation linked {len(node_ids)} canonical graph nodes into a candidate attack path with score {float(payload.get('score', 0.0) or 0.0):.2f}."
    if event_type == "graph_ingest":
        summary = dict(payload.get("attack_graph_summary", {}) or {})
        return (
            f"Result ingestion refreshed the evidence graph to {int(payload.get('hosts', 0) or 0)} hosts and "
            f"{int(summary.get('weighted_edges', 0) or 0)} weighted attack-graph edges."
        )
    if event_type == "phase_internal":
        summary = dict(payload.get("attack_graph_summary", {}) or {})
        if summary:
            return f"Internal phase {payload.get('phase', '')} updated canonical graph state with {int(summary.get('candidate_count', 0) or 0)} ranked paths."
    if event_type == "approval_required":
        return "Human approval is blocking execution until an operator authorizes or rejects the action."
    if event_type == "approval_ok":
        return "Human approval cleared the action and execution can continue."
    if event_type == "approval_denied":
        return "Human review denied the requested action, forcing a safer branch."
    if event_type == "approval_blocked":
        return "Execution paused because approval infrastructure was required but unavailable."
    if event_type == "finding":
        finding = _normalize_value(payload.get("finding", {}))
        return f"New finding from {finding.get('plugin', 'unknown plugin')} added evidence for {finding.get('host', 'unknown host')}."
    return ""


def _graph_change(payload: Dict[str, Any]) -> Dict[str, Any]:
    event_type = str(payload.get("type", "") or "")
    if event_type == "attack_path_generated":
        return {
            "kind": "attack_path",
            "path_id": str(payload.get("path_id", "") or ""),
            "path": list(payload.get("path", []) or []),
            "node_ids": list(payload.get("node_ids", []) or []),
            "finding_ids": list(payload.get("finding_ids", []) or []),
        }
    if event_type == "graph_ingest":
        return {
            "kind": "graph_ingest",
            "focus_node_ids": list(payload.get("focus_node_ids", []) or []),
            "attack_graph_summary": dict(payload.get("attack_graph_summary", {}) or {}),
        }
    if event_type == "phase_internal":
        return {
            "kind": "phase_internal",
            "attack_graph_summary": dict(payload.get("attack_graph_summary", {}) or {}),
            "phase": str(payload.get("phase", "") or ""),
        }
    if event_type == "report_generated":
        return {
            "kind": "report_artifact",
            "artifact_kind": str(payload.get("kind", "") or ""),
            "artifact": str(payload.get("artifact", "") or ""),
        }
    return {}


def _details(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(payload)
    if "finding" in out:
        out["finding"] = _normalize_value(out["finding"])
    if "action" in out:
        out["action"] = _normalize_value(out["action"])
    graph_change = _graph_change(out)
    if graph_change:
        out["graph_change"] = graph_change
    return _normalize_value(out)


def _fallback_items(graph, limit: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for result in list(getattr(graph, "actions", []) or [])[-limit:]:
        action = getattr(result, "action", None)
        items.append(
            {
                "stream_id": str(getattr(result, "ts", "") or ""),
                "channel": "decision",
                "type": "action_complete",
                "event_type": "action_complete",
                "tool": getattr(action, "tool", ""),
                "target": getattr(action, "target", ""),
                "headline": f"Action: {getattr(action, 'tool', '?')} -> {getattr(action, 'target', '?')}",
                "summary": f"returncode {int(getattr(result, 'returncode', 0) or 0)} in phase {getattr(action, 'phase', '')}",
                "phase": str(getattr(action, "phase", "") or ""),
                "created_at": str(getattr(result, "ts", "") or ""),
                "trace_id": "",
                "details": {
                    "tool": getattr(action, "tool", ""),
                    "target": getattr(action, "target", ""),
                    "phase": getattr(action, "phase", ""),
                    "returncode": getattr(result, "returncode", 0),
                    "duration": getattr(result, "duration", 0.0),
                },
            }
        )
    return items


def build_live_stream(*, mission=None, graph=None, event_bus=None, limit: int = 200) -> Dict[str, Any]:
    raw_items: Iterable[Dict[str, Any]]
    if event_bus is not None:
        raw_items = event_bus.timeline(limit=limit)
    else:
        raw_items = _fallback_items(graph, limit)

    items: List[Dict[str, Any]] = []
    counts = {"thinking": 0, "decision": 0, "evidence": 0, "graph_change": 0, "finding": 0, "system": 0}

    for item in raw_items:
        topic = str(item.get("topic", item.get("type", "event")) or "event")
        payload = _normalize_value(item.get("payload", item))
        channel = _channel_for_event(topic, payload)
        counts[channel] = counts.get(channel, 0) + 1
        items.append(
            {
                "stream_id": str(item.get("event_id", item.get("stream_id", item.get("created_at", ""))) or ""),
                "channel": channel,
                "event_type": str(payload.get("type", topic) or topic),
                "headline": _headline(topic, payload, channel),
                "summary": _summary(topic, payload, channel),
                "priority": _priority(topic, payload, channel),
                "operator_action": _operator_action(topic, payload, channel),
                "narrative": _narrative(topic, payload, channel),
                "phase": str(payload.get("phase", "") or ""),
                "created_at": str(item.get("created_at", payload.get("ts", "")) or ""),
                "trace_id": str(item.get("trace_id", payload.get("trace_id", "")) or ""),
                "details": _details(payload),
            }
        )

    return {
        "mission": str(getattr(mission, "name", "") or ""),
        "items": items[-limit:],
        "counts": counts,
    }
