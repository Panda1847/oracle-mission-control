from core.ai.council import CouncilAdvisorClient


class _Client:
    def __init__(self, response, *, ready=True):
        self._response = dict(response)
        self.ready = ready
        self.calls = []

    def decide(self, mission, graph, extra=""):
        self.calls.append(extra)
        return dict(self._response)


def test_council_arbiter_prefers_majority_action():
    proposer = _Client({"action": {"tool": "nmap", "target": "10.0.0.5"}, "reasoning": "scan", "confidence": 0.8})
    critic = _Client({"action": {"tool": "http", "target": "10.0.0.5"}, "reasoning": "safer", "confidence": 0.6})
    verifier = _Client({"action": {"tool": "nmap", "target": "10.0.0.5"}, "reasoning": "verified", "confidence": 0.7})

    council = CouncilAdvisorClient(primary_client=proposer, secondary_client=critic)
    council._call_role = lambda role, mission, graph, extra: {
        "proposer": proposer.decide(mission, graph, council._role_prompt(role, extra)),
        "critic": critic.decide(mission, graph, council._role_prompt(role, extra)),
        "verifier": verifier.decide(mission, graph, council._role_prompt(role, extra)),
    }[role]

    result = council.decide(None, None, "context")

    assert result["action"]["tool"] == "nmap"
    assert result["council"]["arbiter"] in {"proposer", "verifier"}
    assert result["council"]["consensus"]["agreement_count"] == 2
    assert result["council"]["consensus"]["eligible_votes"] == 3
    assert result["council"]["consensus"]["is_split_vote"] is True
    assert result["council"]["roles"]["verifier"]["agrees_with_arbiter"] is True
    assert "COUNCIL ROLE: proposer" in proposer.calls[0]


def test_council_falls_back_to_verifier_on_split_vote():
    proposer = _Client({"action": {"tool": "http", "target": "10.0.0.5"}, "reasoning": "probe", "confidence": 0.6})
    critic = _Client({"action": {"tool": "fuzz", "target": "10.0.0.5"}, "reasoning": "enumerate", "confidence": 0.7})
    verifier = _Client({"action": {"tool": "nmap", "target": "10.0.0.5"}, "reasoning": "confirm", "confidence": 0.8})

    council = CouncilAdvisorClient(primary_client=proposer, secondary_client=critic)
    council._call_role = lambda role, mission, graph, extra: {
        "proposer": proposer.decide(mission, graph, council._role_prompt(role, extra)),
        "critic": critic.decide(mission, graph, council._role_prompt(role, extra)),
        "verifier": verifier.decide(mission, graph, council._role_prompt(role, extra)),
    }[role]

    result = council.decide(None, None, "context")

    assert result["action"]["tool"] == "nmap"
    assert result["council"]["arbiter"] == "verifier"
    assert result["council"]["roles"]["verifier"]["tool"] == "nmap"
    assert result["council"]["roles"]["critic"]["agrees_with_arbiter"] is False
