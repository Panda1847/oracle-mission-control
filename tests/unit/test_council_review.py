from core.ai.council_review import (
    build_council_round,
    extract_council_rounds_from_events,
    extract_council_rounds_from_replay_records,
    summarize_council_rounds,
)


def test_extract_council_rounds_and_review_detect_overrides_and_drift():
    payloads = [
        {
            "type": "ai_decision_result",
            "trace_id": "trace-1",
            "recommended_tool": "nmap",
            "recommended_target": "10.0.0.5",
            "recommendation_confidence": 0.8,
            "recommendation_reasoning": "verify ports",
            "council": {
                "arbiter": "verifier",
                "roles": {"verifier": {"tool": "nmap", "target": "10.0.0.5", "confidence": 0.8}},
                "consensus": {"agreement_count": 2, "eligible_votes": 3, "is_split_vote": True},
            },
        },
        {
            "type": "decision",
            "trace_id": "trace-1",
            "phase": "DISCOVERY",
            "decision_source": "planner_default",
            "gate_reason": "Advisor confidence below threshold.",
            "action": {"tool": "http", "target": "10.0.0.5"},
            "council": {"arbiter": "verifier"},
        },
        {
            "type": "ai_decision_result",
            "trace_id": "trace-2",
            "recommended_tool": "fuzz",
            "recommended_target": "10.0.0.5",
            "recommendation_confidence": 0.75,
            "recommendation_reasoning": "enumerate content",
            "council": {
                "arbiter": "proposer",
                "roles": {"proposer": {"tool": "fuzz", "target": "10.0.0.5", "confidence": 0.75}},
                "consensus": {"agreement_count": 1, "eligible_votes": 3, "is_split_vote": True},
            },
        },
        {
            "type": "decision",
            "trace_id": "trace-2",
            "phase": "ENUMERATION",
            "decision_source": "planner_default",
            "gate_reason": "Advisor chose an action outside the deterministic candidate set.",
            "action": {"tool": "http", "target": "10.0.0.5"},
            "council": {"arbiter": "proposer"},
        },
    ]

    rounds = extract_council_rounds_from_events(payloads)
    review = summarize_council_rounds(rounds)

    assert len(rounds) == 2
    assert rounds[0]["override"] is True
    assert rounds[1]["recommended_tool"] == "fuzz"
    assert review["max_override_streak"] == 2
    assert review["recommendation_drift_count"] == 1
    assert review["arbiter_drift_count"] == 1
    assert "repeated_overrides" in review["alerts"]


def test_extract_council_rounds_from_replay_records_uses_embedded_round():
    round_item = build_council_round(
        {
            "tool": "nmap",
            "target": "10.0.0.9",
            "confidence": 0.82,
            "reasoning": "verify host",
            "council": {"arbiter": "verifier", "roles": {}, "consensus": {"agreement_count": 2, "eligible_votes": 3}},
        },
        final_action={"tool": "nmap", "target": "10.0.0.9"},
        decision_source="advisor",
        phase="DISCOVERY",
    )

    rounds = extract_council_rounds_from_replay_records([{"council_round": round_item}])

    assert rounds[0]["arbiter"] == "verifier"
    assert rounds[0]["outcome"] == "accepted"
