import json
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.engine import MissionEngine
from oracle.core.models import Action, ActionResult, Mission
from oracle.memory.graph import KnowledgeGraph
from oracle.memory.storage import Storage
from oracle.runtime.audit import AuditConfig, AuditLogger


class _BrokenAdvisor:
    def decide(self, mission, graph, extra=""):
        return {"stop_reason": "advisor unavailable"}


class _DeterministicExecutor:
    def __init__(self):
        self.calls = []

    def build_command(self, action):
        return f"run {action.tool} {action.target}"

    def run(self, action):
        self.calls.append((action.phase, action.tool, action.target))
        if action.tool == "nmap":
            parsed = {
                "status": "ok",
                "data": {
                    "ports": [
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache", "state": "open"}
                    ],
                    "os_guess": "Linux",
                },
                "_target": action.target,
                "_cmd": self.build_command(action),
            }
        elif action.tool == "http":
            parsed = {
                "status": "ok",
                "data": {"status_code": 200, "headers": {"server": "Apache"}, "server": "Apache", "powered": ""},
                "_target": action.target,
                "_cmd": self.build_command(action),
            }
        else:
            parsed = {
                "status": "ok",
                "data": {
                    "paths": [{"path": "/admin", "status": 200}],
                    "interesting": [{"path": "/admin", "status": 200}],
                    "count": 1,
                },
                "_target": action.target,
                "_cmd": self.build_command(action),
            }
        return ActionResult(action=action, stdout="", stderr="", returncode=0, duration=0.1, parsed=parsed)


class _AllowAllSafety:
    def validate(self, action, command):
        return True, "OK"


class _CouncilAdvisor:
    def decide(self, mission, graph, extra=""):
        return {
            "action": {"tool": "http", "target": mission.scope[0]},
            "reasoning": "safer probe",
            "confidence": 0.2,
            "council": {
                "arbiter": "verifier",
                "roles": {
                    "proposer": {"tool": "fuzz", "target": mission.scope[0], "confidence": 0.7},
                    "critic": {"tool": "http", "target": mission.scope[0], "confidence": 0.6},
                    "verifier": {"tool": "http", "target": mission.scope[0], "confidence": 0.2, "agrees_with_arbiter": True},
                },
                "consensus": {"agreement_count": 2, "eligible_votes": 3, "is_unanimous": False, "is_split_vote": True},
            },
        }


def test_mission_manager_uses_planner_when_ai_is_unavailable(tmp_path):
    mission = Mission(name="enterprise", scope=["10.0.0.9"], max_iterations=8)
    mission.phase = "INIT"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    executor = _DeterministicExecutor()
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=executor,
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())

    assert any(event["type"] == "decision" for event in events)
    assert any(event.get("decision_source") == "planner_default" for event in events if event["type"] == "decision")
    assert any(event["type"] == "complete" for event in events)
    assert mission.status == "complete"
    assert graph.hosts
    assert executor.calls[0][1] == "nmap"
    internal_phases = {event.get("phase") for event in events if event.get("type") == "phase_internal"}
    assert {"EXPLOIT_ANALYSIS", "POST_PROCESS", "REPORTING"}.issubset(internal_phases)


class _QuarantinedExecutor(_DeterministicExecutor):
    def run(self, action):
        return ActionResult(
            action=action,
            stdout="garbled",
            stderr="",
            returncode=0,
            duration=0.1,
            parsed={"status": "error", "data": {}, "error": "parse_contract_failed:test"},
            parse_valid=False,
            quarantined=True,
            error_kind="parse_contract",
        )


class _BinaryMissingExecutor(_DeterministicExecutor):
    def run(self, action):
        return ActionResult(
            action=action,
            stdout="",
            stderr="Missing binary: nmap",
            returncode=127,
            duration=0.0,
            parsed={"status": "error", "data": {}, "error": "binary missing"},
            binary_missing=True,
            parse_valid=False,
            quarantined=True,
            error_kind="binary_missing",
        )


def test_mission_manager_quarantines_invalid_parse_result(tmp_path):
    mission = Mission(name="quarantine", scope=["10.0.0.9"], max_iterations=2)
    mission.phase = "DISCOVERY"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_QuarantinedExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    assert any(event["type"] == "parse_quarantined" for event in events)
    assert not graph.findings


def test_mission_manager_marks_plugin_unavailable_on_binary_missing(tmp_path):
    mission = Mission(name="missing-bin", scope=["10.0.0.10"], max_iterations=2)
    mission.phase = "DISCOVERY"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_BinaryMissingExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    assert any(event["type"] == "plugin_unavailable" for event in events)
    assert any("marked unavailable" in directive for directive in graph.recent_directives(10))


def test_mission_manager_copilot_mode_always_requires_approval(tmp_path):
    mission = Mission(name="copilot", scope=["10.0.0.9"], max_iterations=2)
    mission.phase = "DISCOVERY"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    approvals = {"count": 0}

    def _approve(_action):
        approvals["count"] += 1
        return True

    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
        approve_cb=_approve,
        opsec={"copilot_mode": True},
    )

    events = list(engine.run())
    assert approvals["count"] >= 1
    assert any(event.get("type") == "approval_required" for event in events)
    assert any(event.get("type") == "approval_ok" for event in events)


def test_exploit_analysis_phase_uses_correlation_paths(tmp_path):
    mission = Mission(name="exploit-analysis-correlation", scope=["10.0.0.22"], max_iterations=2)
    mission.phase = "EXPLOIT_ANALYSIS"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    host = graph.add_host("10.0.0.22")
    host.add_port(80, service="http", version="Apache")
    host.add_port(445, service="smb", version="Samba")
    graph.add_finding(
        severity="MEDIUM",
        title="Web path: /admin [200]",
        description="admin panel exposed",
        host="10.0.0.22",
        port=80,
        plugin="fuzz",
    )

    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    exploit_phase = next(
        event
        for event in events
        if event.get("type") == "phase_internal" and event.get("phase") == "EXPLOIT_ANALYSIS"
    )

    assert exploit_phase.get("attack_paths")
    assert any(event.get("type") == "attack_path_generated" for event in events)
    assert any((finding.plugin or "") == "correlation" for finding in graph.findings)


def test_mission_manager_advisor_state_includes_attack_graph_summary(tmp_path):
    mission = Mission(name="advisor-attack-graph", scope=["10.0.0.44"], max_iterations=2)
    mission.phase = "DISCOVERY"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    host = graph.add_host("10.0.0.44")
    host.add_port(80, service="http", version="Apache")
    graph.add_finding(
        severity="HIGH",
        title="Web path: /admin [200]",
        description="admin panel exposed",
        host="10.0.0.44",
        port=80,
        plugin="fuzz",
    )
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
    )

    state = engine._build_advisor_state(engine.state_machine.normalize(mission.phase), [], "need more evidence", {})

    assert state["attack_graph_summary"]["nodes"] >= 1
    assert "top_paths" in state["attack_graph_summary"]


def test_reporting_phase_emits_report_generated_events(tmp_path):
    mission = Mission(name="reporting-events", scope=["10.0.0.30"], max_iterations=8)
    mission.phase = "INIT"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    report_events = [event for event in events if event.get("type") == "report_generated"]
    assert report_events
    assert any(event.get("kind") == "bundle_json" for event in report_events)
    assert any(event.get("kind") == "intelligence_json" for event in report_events)
    assert any(event.get("kind") == "mission_package_zip" for event in report_events)
    snapshot = graph.to_dict()
    assert snapshot.get("latest_report")

    intelligence_event = next(event for event in report_events if event.get("kind") == "intelligence_json")
    with open(intelligence_event["artifact"], "r", encoding="utf-8") as handle:
        intelligence_artifact = json.load(handle)
    assert intelligence_artifact == snapshot.get("latest_report")

    package_event = next(event for event in report_events if event.get("kind") == "mission_package_zip")
    archive = zipfile.ZipFile(io.BytesIO(Path(package_event["artifact"]).read_bytes()))
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    packaged_intelligence = json.loads(archive.read("reports/intelligence.json").decode("utf-8"))
    assert manifest["mission"] == mission.name
    assert packaged_intelligence == snapshot.get("latest_report")
    assert "exports/executive_summary.md" in archive.namelist()
    assert "exports/findings.json" in archive.namelist()
    assert "exports/replay.jsonl" in archive.namelist()


def test_mission_manager_checkpoints_include_replay_artifacts(tmp_path):
    mission = Mission(name="replay-artifacts", scope=["10.0.0.40"], max_iterations=4)
    mission.phase = "INIT"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    checkpoints = [event for event in events if event.get("type") == "checkpoint"]

    assert checkpoints
    replay_artifacts = [event.get("replay_artifact", "") for event in checkpoints if event.get("replay_artifact")]
    assert replay_artifacts

    loaded = json.loads(Path(replay_artifacts[0]).read_text(encoding="utf-8"))
    assert loaded["mission"] == "replay-artifacts"
    assert "graph_snapshot_before" in loaded
    assert "graph_snapshot_after" in loaded
    assert "planner_extra" in loaded
    assert "state_hash" in loaded


def test_mission_manager_replay_artifacts_include_council_round_context(tmp_path):
    mission = Mission(name="replay-council", scope=["10.0.0.44"], max_iterations=2)
    mission.phase = "DISCOVERY"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_CouncilAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
    )

    events = list(engine.run())
    checkpoint = next(event for event in events if event.get("type") == "checkpoint" and event.get("replay_artifact"))
    loaded = json.loads(Path(checkpoint["replay_artifact"]).read_text(encoding="utf-8"))

    assert loaded["decision_source"] == "planner_default"
    assert loaded["gate_reason"]
    assert loaded["council_round"]["arbiter"] == "verifier"
    assert loaded["council_round"]["override"] is True
    assert loaded["council_round"]["recommended_tool"] == "http"
    assert loaded["council_round"]["final_tool"] == "nmap"


def test_mission_manager_audit_chain_references_replay_artifacts(tmp_path):
    mission = Mission(name="audit-replay", scope=["10.0.0.41"], max_iterations=4)
    mission.phase = "INIT"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    audit = AuditLogger(AuditConfig(path=tmp_path / "audit.jsonl"))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
        audit=audit,
    )

    list(engine.run())

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    checkpoint_events = [json.loads(line) for line in lines if '"event":"iteration_checkpoint"' in line]
    assert checkpoint_events
    assert any(event["payload"].get("replay_artifact") for event in checkpoint_events)


def test_mission_manager_audit_cycle_shares_replay_provenance(tmp_path):
    mission = Mission(name="audit-provenance", scope=["10.0.0.42"], max_iterations=4)
    mission.phase = "INIT"
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    audit = AuditLogger(AuditConfig(path=tmp_path / "audit-provenance.jsonl"))
    engine = MissionEngine(
        mission=mission,
        graph=graph,
        ai=_BrokenAdvisor(),
        executor=_DeterministicExecutor(),
        safety=_AllowAllSafety(),
        audit=audit,
    )

    list(engine.run())

    rows = [json.loads(line) for line in (tmp_path / "audit-provenance.jsonl").read_text(encoding="utf-8").splitlines()]
    checkpoint = next(row for row in rows if row["event"] == "iteration_checkpoint" and row["payload"].get("replay_artifact"))
    replay_id = checkpoint["payload"]["replay_id"]
    linked = [row for row in rows if row.get("payload", {}).get("replay_id") == replay_id]

    assert replay_id
    assert any(row["event"] == "decision" for row in linked)
    assert any(row["event"] == "result" for row in linked)
    assert checkpoint["payload"]["replay_artifact"]

    artifact = json.loads(Path(checkpoint["payload"]["replay_artifact"]).read_text(encoding="utf-8"))
    assert artifact["replay_id"] == replay_id
