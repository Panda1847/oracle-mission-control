"""Mission control-plane serializers."""

from __future__ import annotations

from typing import Any, Dict, List

from core.ai.council_review import extract_council_rounds_from_events, summarize_council_rounds
from core.attackgraph import attack_graph_summary, build_attack_graph
from memory.replay import ReplayStore
from oracle import get_build_identity

from .plugins import plugin_snapshot


def _event_payloads(event_bus, *, limit: int = 500) -> List[Dict[str, Any]]:
    if event_bus is None:
        return []
    items = []
    for item in event_bus.timeline(limit=limit):
        payload = dict(item.get("payload", {}) or {})
        payload.setdefault("type", str(payload.get("type", item.get("topic", "event")) or "event"))
        payload.setdefault("created_at", str(item.get("created_at", "") or ""))
        payload.setdefault("trace_id", str(item.get("trace_id", "") or ""))
        items.append(payload)
    return items


def _council_roles(council: Dict[str, Any]) -> List[Dict[str, Any]]:
    roles = dict(council.get("roles", {}) or {})
    items: List[Dict[str, Any]] = []
    for role, payload in roles.items():
        entry = dict(payload or {})
        action = dict(entry.get("action", {}) or {})
        items.append(
            {
                "role": str(role or ""),
                "tool": str(entry.get("tool", action.get("tool", "")) or ""),
                "target": str(entry.get("target", action.get("target", "")) or ""),
                "confidence": float(entry.get("confidence", 0.0) or 0.0),
                "reasoning": str(entry.get("reasoning", "") or ""),
                "stop_reason": str(entry.get("stop_reason", "") or ""),
                "agrees_with_arbiter": bool(entry.get("agrees_with_arbiter", False)),
            }
        )
    return sorted(items, key=lambda item: (item["role"] != "verifier", item["role"] != "proposer", item["role"]))


def _recent_council_rounds(decision_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for event in reversed(decision_events):
        council = dict(event.get("council", {}) or {})
        if not council:
            continue
        action = dict(event.get("action", {}) or {})
        items.append(
            {
                "phase": str(event.get("phase", "") or ""),
                "decision_source": str(event.get("decision_source", "") or ""),
                "outcome": "accepted" if str(event.get("decision_source", "") or "") == "advisor" else "fallback",
                "arbiter": str(council.get("arbiter", "") or ""),
                "tool": str(action.get("tool", "") or ""),
                "target": str(action.get("target", "") or ""),
                "confidence": float(event.get("confidence", 0.0) or 0.0),
                "gate_reason": str(event.get("gate_reason", "") or ""),
                "created_at": str(event.get("created_at", "") or ""),
            }
        )
        if len(items) >= 5:
            break
    return items


def _replay_summary(graph) -> Dict[str, Any]:
    storage = getattr(graph, "_storage", None)
    base_dir = getattr(storage, "base_dir", None)
    if base_dir is None:
        return {"count": 0, "latest_replay_id": "", "latest_artifact": ""}
    store = ReplayStore(base_dir / "replay")
    mission_id = str(getattr(graph, "mission_id", "") or "")
    items = store.list(mission_id)
    if not items:
        return {"count": 0, "latest_replay_id": "", "latest_artifact": ""}
    latest = store.load(items[-1])
    return {
        "count": len(items),
        "latest_replay_id": str(latest.get("replay_id", "") or ""),
        "latest_artifact": str(items[-1]),
        "latest_phase": str(latest.get("phase", "") or ""),
    }


def _analyst_findings(graph_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    latest_report = dict(graph_dict.get("latest_report", {}) or {})
    ranked = list(latest_report.get("ranked_findings", []) or list(graph_dict.get("findings", []) or []))
    items: List[Dict[str, Any]] = []
    for item in ranked[:25]:
        if not isinstance(item, dict):
            continue
        evidence = str(item.get("evidence", "") or "").strip()
        items.append(
            {
                "title": str(item.get("title", "") or ""),
                "host": str(item.get("host", "") or ""),
                "port": int(item.get("port", 0) or 0),
                "severity": str(item.get("severity", "INFO") or "INFO"),
                "confidence": float(item.get("confidence", 0.0) or 0.0),
                "cves": list(item.get("cves", []) or []),
                "plugin": str(item.get("plugin", "") or ""),
                "evidence_refs": [evidence] if evidence else [],
            }
        )
    return items


def _council_summary(event_bus) -> Dict[str, Any]:
    payloads = _event_payloads(event_bus)
    ai_events = [item for item in payloads if str(item.get("type", "")) == "ai_decision_result"]
    decision_events = [item for item in payloads if str(item.get("type", "")) == "decision"]
    council_rounds = extract_council_rounds_from_events(payloads)
    review = summarize_council_rounds(council_rounds)
    latest_ai = ai_events[-1] if ai_events else {}
    latest_decision = decision_events[-1] if decision_events else {}
    latest_council = next(
        (
            item
            for item in reversed(decision_events)
            if isinstance(item.get("council"), dict) and str((item.get("council") or {}).get("arbiter", "") or "")
        ),
        {},
    )
    action = dict(latest_decision.get("action", {}) or {})
    latest_roles = list(dict((latest_council.get("council", {}) or {}).get("roles", {}) or {}).keys())
    backend = str(latest_ai.get("backend", "") or "")
    arbiter = str(latest_ai.get("council_arbiter", "") or "") or str((latest_council.get("council", {}) or {}).get("arbiter", "") or "")
    council_meta = dict(latest_ai.get("council", {}) or latest_council.get("council", {}) or {})
    consensus = dict(council_meta.get("consensus", {}) or {})
    mode = "deterministic"
    if backend == "council" or arbiter:
        mode = "council"
    elif backend:
        mode = backend
    return {
        "mode": mode,
        "backend": backend or "unknown",
        "active": bool(backend == "council" or arbiter),
        "last_arbiter": arbiter,
        "last_phase": str(latest_decision.get("phase", latest_ai.get("phase", "")) or ""),
        "recommendations_seen": len(ai_events),
        "accepted_count": int(review.get("accepted_count", 0) or 0),
        "fallback_count": int(review.get("fallback_count", 0) or 0),
        "last_recommended_tool": str(latest_ai.get("recommended_tool", "") or ""),
        "last_recommended_target": str(latest_ai.get("recommended_target", "") or ""),
        "last_decision_source": str(latest_decision.get("decision_source", "") or ""),
        "last_decision_tool": str(action.get("tool", "") or ""),
        "last_decision_target": str(action.get("target", "") or ""),
        "last_decision_outcome": "accepted" if str(latest_decision.get("decision_source", "") or "") == "advisor" else "fallback",
        "last_gate_reason": str(latest_decision.get("gate_reason", "") or ""),
        "last_decision_confidence": float(latest_decision.get("confidence", 0.0) or 0.0),
        "last_recommendation_confidence": float(latest_ai.get("recommendation_confidence", 0.0) or 0.0),
        "last_recommendation_reasoning": str(latest_ai.get("recommendation_reasoning", "") or ""),
        "last_roles": latest_roles,
        "role_breakdown": _council_roles(council_meta),
        "agreement_count": int(consensus.get("agreement_count", 0) or 0),
        "eligible_votes": int(consensus.get("eligible_votes", 0) or 0),
        "is_unanimous": bool(consensus.get("is_unanimous", False)),
        "is_split_vote": bool(consensus.get("is_split_vote", False)),
        "recent_rounds": _recent_council_rounds(decision_events),
        "current_override_streak": int(review.get("current_override_streak", 0) or 0),
        "max_override_streak": int(review.get("max_override_streak", 0) or 0),
        "recommendation_drift_count": int(review.get("recommendation_drift_count", 0) or 0),
        "final_action_drift_count": int(review.get("final_action_drift_count", 0) or 0),
        "arbiter_drift_count": int(review.get("arbiter_drift_count", 0) or 0),
        "split_vote_count": int(review.get("split_vote_count", 0) or 0),
        "override_rate": float(review.get("override_rate", 0.0) or 0.0),
        "last_drift": dict(review.get("last_drift", {}) or {}),
        "alerts": list(review.get("alerts", []) or []),
        "recent_overrides": list(review.get("recent_overrides", []) or []),
        "last_event_at": str(latest_decision.get("created_at", latest_ai.get("created_at", "")) or ""),
    }


def mission_snapshot(mission, graph, *, event_bus=None, plugin_registry=None) -> Dict[str, Any]:
    if mission is None or graph is None:
        return {"status": "unavailable", "stats": {"hosts": 0, "findings": 0}}
    graph_dict = graph.to_dict()
    latest_report = dict(graph_dict.get("latest_report", {}) or {})
    attack_graph = dict(latest_report.get("attack_graph", {}) or {})
    if not attack_graph:
        attack_graph = build_attack_graph(graph_dict)
    attack_graph_data = dict(latest_report.get("attack_graph_summary", {}) or attack_graph_summary(attack_graph))
    attack_graph_nodes = sorted(
        list(attack_graph.get("nodes", []) or []),
        key=lambda item: (float(item.get("risk_score", 0.0) or 0.0), float(item.get("weight", 0.0) or 0.0), str(item.get("id", ""))),
        reverse=True,
    )
    attack_graph_edges = sorted(
        list(attack_graph.get("edges", []) or []),
        key=lambda item: (float(item.get("weight", 0.0) or 0.0), str(item.get("id", ""))),
        reverse=True,
    )
    return {
        "name": mission.name,
        "scope": list(getattr(mission, "scope", [])),
        "objective": getattr(mission, "objective", ""),
        "phase": getattr(mission, "phase", "INIT"),
        "status": getattr(mission, "status", "unknown"),
        "iterations": getattr(mission, "iterations", 0),
        "stats": graph_dict.get("stats", {}),
        "topology": graph_dict.get("topology", {}),
        "attack_graph": {
            "nodes": int(attack_graph_data.get("nodes", len(list(graph_dict.get("topology", {}).get("nodes", []) or []))) or 0),
            "edges": int(attack_graph_data.get("edges", len(list(graph_dict.get("topology", {}).get("edges", []) or []))) or 0),
            "candidate_count": int(attack_graph_data.get("candidate_count", 0) or 0),
            "weighted_edges": int(attack_graph_data.get("weighted_edges", 0) or 0),
            "highest_path_score": float(attack_graph_data.get("highest_path_score", 0.0) or 0.0),
            "top_paths": list(attack_graph_data.get("top_paths", []) or [])[:5],
            "top_nodes": [
                {
                    "id": str(item.get("id", "") or ""),
                    "label": str(item.get("label", "") or ""),
                    "kind": str(item.get("kind", "") or ""),
                    "risk_score": float(item.get("risk_score", 0.0) or 0.0),
                    "weight": float(item.get("weight", 0.0) or 0.0),
                }
                for item in attack_graph_nodes[:5]
            ],
            "top_edges": [
                {
                    "id": str(item.get("id", "") or ""),
                    "from": str(item.get("from", "") or ""),
                    "to": str(item.get("to", "") or ""),
                    "kind": str(item.get("kind", "") or ""),
                    "weight": float(item.get("weight", 0.0) or 0.0),
                }
                for item in attack_graph_edges[:5]
            ],
        },
        "analyst_findings": _analyst_findings(graph_dict),
        "replay_summary": _replay_summary(graph),
        "council": _council_summary(event_bus),
        "build_identity": get_build_identity(),
        "plugins": plugin_snapshot(plugin_registry),
        "recent_directives": graph.recent_directives(10),
        "timeline_depth": len(event_bus.timeline(limit=500)) if event_bus else len(getattr(graph, "actions", [])),
    }


def mission_timeline(mission, graph, *, event_bus=None, limit: int = 200) -> List[Dict[str, Any]]:
    if event_bus is not None:
        return event_bus.timeline(limit=limit)
    items = []
    for result in getattr(graph, "actions", [])[-limit:]:
        items.append(
            {
                "topic": "action_complete",
                "created_at": result.ts,
                "payload": {
                    "tool": result.action.tool,
                    "target": result.action.target,
                    "phase": result.action.phase,
                    "returncode": result.returncode,
                    "duration": result.duration,
                },
            }
        )
    return items
