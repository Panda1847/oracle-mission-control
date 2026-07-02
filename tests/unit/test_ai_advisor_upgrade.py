from core.ai.advisor import AIAdvisor
from core.ai.response_validator import RecommendationValidator
from oracle.core.models import Action


class _BadAdvisor:
    ready = False

    def decide(self, mission, graph, extra=""):
        return {"action": {"tool": "sqlmap", "target": "10.0.0.1"}, "confidence": 1.0}


class _RecordingAdvisor:
    ready = True

    def __init__(self):
        self.last_extra = ""

    def decide(self, mission, graph, extra=""):
        self.last_extra = extra
        return {"action": {"tool": "nmap", "target": "10.0.0.1"}, "confidence": 0.8}


class _CouncilAdvisor:
    ready = True

    def decide(self, mission, graph, extra=""):
        return {
            "action": {"tool": "nmap", "target": "10.0.0.1"},
            "reasoning": "verified",
            "confidence": 0.75,
            "council": {"arbiter": "verifier", "roles": {"verifier": {"confidence": 0.75}}},
        }


def test_ai_advisor_uses_local_fallback_for_invalid_remote_action():
    candidates = [Action(tool="nmap", target="10.0.0.1", args={}, confidence=0.8, expected="ports")]
    advisor = AIAdvisor(_BadAdvisor())
    recommendation = advisor.recommend(None, None, "DISCOVERY", candidates, "need scan")
    assert recommendation is not None
    assert recommendation["tool"] == "nmap"


def test_response_validator_rejects_unlisted_candidate():
    validator = RecommendationValidator()
    result = validator.validate(
        {
            "action": {"tool": "http", "target": "10.0.0.2"},
            "reasoning": "x",
            "expected": "y",
            "confidence": 0.9,
        },
        [Action(tool="nmap", target="10.0.0.1", args={})],
    )
    assert result is None


def test_response_validator_preserves_council_metadata():
    validator = RecommendationValidator()
    result = validator.validate(
        {
            "action": {"tool": "nmap", "target": "10.0.0.1"},
            "reasoning": "verified",
            "expected": "ports",
            "confidence": 0.7,
            "council": {"arbiter": "verifier", "roles": {"verifier": {"confidence": 0.7}}},
        },
        [Action(tool="nmap", target="10.0.0.1", args={})],
    )
    assert result is not None
    assert result["council"]["arbiter"] == "verifier"


def test_ai_advisor_prompt_includes_attack_graph_summary():
    candidates = [Action(tool="nmap", target="10.0.0.1", args={}, confidence=0.8, expected="ports")]
    recorder = _RecordingAdvisor()
    advisor = AIAdvisor(recorder)

    recommendation = advisor.recommend(
        None,
        None,
        "DISCOVERY",
        candidates,
        "need scan",
        advisor_state={
            "attack_graph_summary": {
                "nodes": 3,
                "edges": 2,
                "candidate_count": 1,
                "highest_path_score": 0.91,
            }
        },
    )

    assert recommendation is not None
    assert "ATTACK GRAPH SUMMARY:" in recorder.last_extra
    assert "'candidate_count': 1" in recorder.last_extra


def test_ai_advisor_preserves_council_metadata():
    candidates = [Action(tool="nmap", target="10.0.0.1", args={}, confidence=0.8, expected="ports")]
    advisor = AIAdvisor(_CouncilAdvisor())

    recommendation = advisor.recommend(None, None, "DISCOVERY", candidates, "need scan")

    assert recommendation is not None
    assert recommendation["council"]["arbiter"] == "verifier"
