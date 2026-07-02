import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.orchestrator.artifact_router import ArtifactRouter
from core.orchestrator.event_bus import EventBus
from core.orchestrator.dispatcher import Dispatcher
from core.reporting.intelligence_report import build_intelligence_report
from oracle.core.models import Mission
from oracle.memory.graph import KnowledgeGraph
from oracle.memory.storage import Storage
from oracle.plugins.base import PluginRegistry, ToolPlugin
from oracle.runtime.executor import Executor
from memory.replay import ReplayStore
from web.backend_gateway import create_gateway


class EchoPlugin(ToolPlugin):
    name = "echo"
    description = "echo"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "printf 'ok'"

    def parse(self, stdout, stderr):
        return {"status": "ok", "data": {"message": stdout}}


def test_control_plane_gateway_endpoints(tmp_path):
    mission = Mission(name="cp", scope=["127.0.0.1"])
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    graph.add_chat_message("operator", "hello")
    graph.add_directive("pause if needed")
    graph.add_host("127.0.0.1", os_guess="Linux")
    graph.add_finding(title="HTTP exposed", host="127.0.0.1", port=80, severity="HIGH", plugin="http", evidence="service:127.0.0.1:80")
    graph.add_report(build_intelligence_report(mission.name, graph.to_dict(), mission_snapshot={"phase": "REPORTING"}))

    registry = PluginRegistry()
    registry._plugins["echo"] = EchoPlugin()
    executor = Executor(registry)
    dispatcher = Dispatcher(executor)
    event_bus = EventBus()
    event_bus.publish("mission.event", {"value": 1}, trace_id="t-1")
    event_bus.publish(
        "ai_decision_result",
        {
            "type": "ai_decision_result",
            "backend": "council",
            "council_arbiter": "verifier",
            "phase": "DISCOVERY",
            "has_recommendation": True,
            "recommended_tool": "nmap",
            "recommended_target": "127.0.0.1",
            "recommendation_confidence": 0.81,
            "recommendation_reasoning": "verified path",
            "council": {
                "arbiter": "verifier",
                "roles": {
                    "proposer": {"tool": "nmap", "target": "127.0.0.1", "confidence": 0.7},
                    "critic": {"tool": "http", "target": "127.0.0.1", "confidence": 0.4},
                    "verifier": {"tool": "nmap", "target": "127.0.0.1", "confidence": 0.81, "agrees_with_arbiter": True},
                },
                "consensus": {"agreement_count": 2, "eligible_votes": 3, "is_unanimous": False, "is_split_vote": True},
            },
        },
        trace_id="t-1",
    )
    event_bus.publish(
        "decision",
        {
            "type": "decision",
            "phase": "DISCOVERY",
            "decision_source": "advisor",
            "action": {"tool": "nmap", "target": "127.0.0.1"},
            "council": {"arbiter": "verifier", "roles": {"proposer": "gpt", "verifier": "gpt"}},
        },
        trace_id="t-1",
    )
    event_bus.publish(
        "approval_required",
        {"type": "approval_required", "tool": "nmap", "target": "127.0.0.1", "phase": "DISCOVERY"},
        trace_id="t-1",
    )
    ReplayStore(tmp_path / "replay").create("cp", {"mission": "cp", "replay_id": "abc123", "phase": "REPORTING"}, branch="reporting")
    artifacts = ArtifactRouter(tmp_path / "artifacts")
    artifacts.route("reports", "demo", {"ok": True}, extension=".json")

    app = create_gateway(
        mission=mission,
        graph=graph,
        dispatcher=dispatcher,
        plugin_registry=registry,
        event_bus=event_bus,
        artifact_router=artifacts,
    )
    client = app.test_client()
    try:
        assert client.get("/healthz").status_code == 200
        assert client.get("/api/dashboard/overview").status_code == 200
        overview = client.get("/api/dashboard/overview").get_json()
        assert overview["build_identity"]["semantic_version"]
        assert overview["replay_summary"]["count"] == 1
        assert overview["analyst_findings"]
        assert "weighted_edges" in overview["attack_graph"]
        assert overview["attack_graph"]["top_nodes"]
        assert overview["council"]["mode"] == "council"
        assert overview["council"]["last_arbiter"] == "verifier"
        assert overview["council"]["accepted_count"] == 1
        assert overview["council"]["agreement_count"] == 2
        assert overview["council"]["is_split_vote"] is True
        assert overview["council"]["role_breakdown"][0]["role"] == "verifier"
        assert overview["council"]["max_override_streak"] == 0
        assert overview["council"]["alerts"] == []
        live_stream = client.get("/api/dashboard/live-stream").get_json()
        assert "items" in live_stream
        assert live_stream["items"][1]["priority"] == "medium"
        assert "completed split arbitration" in live_stream["items"][1]["narrative"]
        assert live_stream["items"][3]["priority"] == "high"
        assert "Review and approve or deny" in live_stream["items"][3]["operator_action"]
        assert client.get("/api/dashboard/workers").status_code == 200
        assert client.get("/api/dashboard/plugins").status_code == 200
        assert client.get("/api/dashboard/evidence").status_code == 200
        assert client.get("/api/dashboard/timeline").status_code == 200
        assert client.get("/api/dashboard/artifacts").status_code == 200
        artifact_listing = client.get("/api/dashboard/artifacts").get_json()["items"]
        download_path = artifact_listing[0]["download_url"]
        downloaded = client.get(download_path)
        assert downloaded.status_code == 200
        assert downloaded.get_json()["ok"] is True
        assert client.get("/api/dashboard/chat").status_code == 200
    finally:
        dispatcher.shutdown()


def test_control_plane_gateway_blocks_remote_when_auth_missing(tmp_path):
    mission = Mission(name="cp-auth", scope=["127.0.0.1"])
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    app = create_gateway(mission=mission, graph=graph)
    client = app.test_client()

    local = client.get("/api/dashboard/overview")
    remote = client.get("/api/dashboard/overview", environ_base={"REMOTE_ADDR": "10.10.10.20"})

    assert local.status_code == 200
    assert remote.status_code == 401


def test_control_plane_gateway_token_auth_and_rate_limit(tmp_path):
    mission = Mission(name="cp-rate", scope=["127.0.0.1"])
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    app = create_gateway(mission=mission, graph=graph, auth_token="secret-token")
    client = app.test_client()

    # Seed cookie via index token query, then use dashboard APIs.
    assert client.get("/?token=secret-token").status_code == 200
    assert client.get("/api/dashboard/overview").status_code == 200

    status_codes = []
    for _ in range(24):
        status_codes.append(client.get("/api/dashboard/export").status_code)
    assert 429 in status_codes
