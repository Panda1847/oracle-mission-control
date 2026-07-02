from core.orchestrator.event_bus import EventBus
from dashboard.live_stream import build_live_stream


class _Mission:
    name = "live-stream"


def test_build_live_stream_classifies_dashboard_channels():
    bus = EventBus()
    bus.publish("thinking", {"type": "thinking", "iteration": 3, "phase": "DISCOVERY"}, trace_id="trace-1")
    bus.publish(
        "decision",
        {"type": "decision", "tool": "nmap", "target": "10.0.0.5", "phase": "DISCOVERY", "reasoning": "scan first"},
        trace_id="trace-1",
    )
    bus.publish("graph_ingest", {"type": "graph_ingest", "hosts": 2, "findings": 1, "phase": "ENUMERATION"}, trace_id="trace-1")
    bus.publish(
        "finding",
        {
            "type": "finding",
            "phase": "ENUMERATION",
            "finding": {"severity": "HIGH", "title": "HTTP exposed", "host": "10.0.0.5", "port": 80},
        },
        trace_id="trace-1",
    )
    bus.publish("parse_quarantined", {"type": "parse_quarantined", "tool": "http", "reason": "bad parser"}, trace_id="trace-2")

    stream = build_live_stream(mission=_Mission(), graph=None, event_bus=bus, limit=20)

    assert stream["mission"] == "live-stream"
    assert stream["counts"]["thinking"] == 1
    assert stream["counts"]["decision"] == 1
    assert stream["counts"]["graph_change"] == 1
    assert stream["counts"]["finding"] == 1
    assert stream["counts"]["evidence"] == 1
    assert stream["items"][0]["headline"] == "Iteration 3 reasoning"
    assert stream["items"][1]["summary"] == "scan first"
    assert stream["items"][3]["summary"] == "HIGH on 10.0.0.5:80"
    assert stream["items"][2]["details"]["graph_change"]["kind"] == "graph_ingest"


def test_build_live_stream_falls_back_to_graph_actions():
    class _Action:
        tool = "http"
        target = "10.0.0.7"
        phase = "ENUMERATION"

    class _Result:
        ts = "2026-04-28T12:00:00Z"
        action = _Action()
        returncode = 0
        duration = 0.2

    class _Graph:
        actions = [_Result()]

    stream = build_live_stream(mission=_Mission(), graph=_Graph(), event_bus=None, limit=5)

    assert stream["counts"]["decision"] == 1
    assert stream["items"][0]["event_type"] == "action_complete"
    assert stream["items"][0]["headline"] == "Action: http -> 10.0.0.7"


def test_build_live_stream_reads_nested_decision_action_and_path_projection():
    bus = EventBus()
    bus.publish(
        "decision",
        {
            "type": "decision",
            "action": {"tool": "nmap", "target": "10.0.0.9"},
            "reasoning": "selected by gate",
            "phase": "DISCOVERY",
        },
        trace_id="trace-9",
    )
    bus.publish(
        "attack_path_generated",
        {
            "type": "attack_path_generated",
            "path": ["10.0.0.9:web:80", "10.0.0.9:credential-context:80"],
            "path_id": "path:demo",
            "node_ids": ["svc:10.0.0.9:http:80", "cred:10.0.0.9"],
            "finding_ids": ["f1"],
            "score": 0.8,
        },
        trace_id="trace-9",
    )

    stream = build_live_stream(mission=_Mission(), graph=None, event_bus=bus, limit=10)

    assert stream["items"][0]["headline"] == "Decision: nmap -> 10.0.0.9"
    assert stream["items"][1]["details"]["graph_change"]["path_id"] == "path:demo"
    assert stream["items"][1]["details"]["graph_change"]["node_ids"] == ["svc:10.0.0.9:http:80", "cred:10.0.0.9"]


def test_build_live_stream_adds_narrative_and_operator_actions():
    bus = EventBus()
    bus.publish(
        "ai_decision_result",
        {
            "type": "ai_decision_result",
            "backend": "council",
            "council_arbiter": "verifier",
            "has_recommendation": True,
            "recommended_tool": "nmap",
            "recommended_target": "10.0.0.8",
            "council": {"consensus": {"agreement_count": 2, "eligible_votes": 3, "is_unanimous": False, "is_split_vote": True}},
        },
        trace_id="trace-council",
    )
    bus.publish(
        "approval_required",
        {"type": "approval_required", "tool": "nmap", "target": "10.0.0.8", "phase": "DISCOVERY"},
        trace_id="trace-council",
    )

    stream = build_live_stream(mission=_Mission(), graph=None, event_bus=bus, limit=10)

    assert "completed split arbitration" in stream["items"][0]["narrative"]
    assert stream["items"][0]["priority"] == "medium"
    assert stream["items"][1]["priority"] == "high"
    assert "Review and approve or deny" in stream["items"][1]["operator_action"]


def test_build_live_stream_explains_council_override_fallback():
    bus = EventBus()
    bus.publish(
        "decision",
        {
            "type": "decision",
            "phase": "DISCOVERY",
            "decision_source": "planner_default",
            "gate_reason": "Advisor confidence 0.20 is below required threshold 0.60.",
            "action": {"tool": "http", "target": "10.0.0.9"},
            "council": {"arbiter": "verifier"},
        },
        trace_id="trace-override",
    )

    stream = build_live_stream(mission=_Mission(), graph=None, event_bus=bus, limit=10)

    assert "overrode the council recommendation" in stream["items"][0]["narrative"]
    assert "Review why the confidence gate overrode the council recommendation" in stream["items"][0]["operator_action"]
