import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.orchestrator.job_tracker import JobTracker
from core.planner.confidence_gate import ConfidenceGate
from core.planner.phase_controller import PhaseController
from core.planner.retry_engine import RetryEngine
from core.planner.state_machine import MissionPhase, MissionStateMachine
from core.policy.policy_engine import PolicyEngine
from oracle.core.models import Action, ActionResult, Mission
from oracle.core.planner import Planner
from oracle.memory.graph import KnowledgeGraph
from oracle.memory.storage import Storage


def make_graph(tmp_path):
    return KnowledgeGraph("planner_test", Storage(tmp_path))


def test_state_machine_allows_only_legal_transitions():
    sm = MissionStateMachine()
    assert sm.can_transition(MissionPhase.DISCOVERY, MissionPhase.ENUMERATION)
    assert not sm.can_transition(MissionPhase.DISCOVERY, MissionPhase.REPORTING)


def test_phase_controller_moves_init_to_discovery_and_builds_scan_candidates(tmp_path):
    mission = Mission(name="m1", scope=["10.0.0.1"], max_iterations=5)
    mission.phase = "INIT"
    graph = make_graph(tmp_path)
    controller = PhaseController()
    tracker = JobTracker()

    plan = controller.plan(mission, graph, tracker)

    assert plan.transitions
    assert plan.transitions[0].new == MissionPhase.DISCOVERY
    assert plan.phase == MissionPhase.DISCOVERY
    assert plan.candidates
    assert plan.candidates[0].tool == "nmap"
    assert plan.candidates[0].target == "10.0.0.1"


def test_confidence_gate_rejects_low_confidence_recommendation():
    policy = PolicyEngine()
    gate = ConfidenceGate(policy)
    candidate = Action(
        tool="nmap",
        target="10.0.0.1",
        args={"ports": "80"},
        confidence=0.55,
        reasoning="planner default",
        phase="DISCOVERY",
        timeout=60,
    )

    decision = gate.select(
        "DISCOVERY",
        [candidate],
        {"tool": "nmap", "target": "10.0.0.1", "confidence": 0.10, "reasoning": "low confidence"},
    )

    assert decision.source == "planner_default"
    assert not decision.accepted
    assert decision.action.tool == "nmap"


def test_retry_engine_escalates_timeout_after_failure():
    policy = PolicyEngine()
    retries = RetryEngine(policy)
    tracker = JobTracker()
    action = Action(
        tool="http",
        target="10.0.0.5",
        args={"port": 80, "path": "/"},
        confidence=0.6,
        reasoning="validate service",
        phase="VALIDATION",
        timeout=25,
    )
    result = ActionResult(
        action=action,
        stdout="",
        stderr="boom",
        returncode=-1,
        duration=0.1,
        parsed={},
    )
    tracker.record_result(result)

    retry = retries.build_retry(action, tracker)

    assert retry is not None
    assert retry.timeout > action.timeout
    assert "Retry attempt" in retry.reasoning


def test_compat_planner_exploit_analysis_uses_attack_candidates(tmp_path):
    mission = Mission(name="m-exploit", scope=["10.0.0.2"], max_iterations=4)
    mission.phase = "EXPLOIT_ANALYSIS"
    graph = make_graph(tmp_path)
    host = graph.add_host("10.0.0.2")
    host.add_port(80, service="http", version="Apache")
    host.add_port(445, service="smb", version="Samba")
    graph.add_finding(
        severity="MEDIUM",
        title="Web path: /admin [200]",
        description="admin panel exposed",
        host="10.0.0.2",
        port=80,
        plugin="fuzz",
    )

    planner = Planner()
    next_action = planner.next_exploit_action(graph)
    description = planner.evaluate(mission, graph)
    context = planner.controller.phase_context(mission, graph, planner.tracker)

    assert next_action
    assert next_action["score"] > 0.0
    assert "TOP ATTACK PATHS" in description
    assert "CONFIDENCE GAPS" in description
    assert "GRAPH STATE" in description
    assert context["graph_state"]["hosts"] == 1
    assert context["attack_candidates"]
    assert context["next_exploit_action"]["path"]
