import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.orchestrator.event_bus import EventBus
from core.orchestrator.artifact_router import ArtifactRouter
from oracle.core.models import Mission
from oracle.memory.graph import KnowledgeGraph
from oracle.memory.storage import Storage
from api.app import create_app


def _auth_header(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_operator_api_enforces_rbac_and_session_ownership(tmp_path):
    artifact_router = ArtifactRouter(tmp_path / "artifacts")
    artifact_router.route("reports", "demo", {"ok": True}, extension=".json")
    mission = Mission(name="m1", scope=["10.0.0.5"])
    graph = KnowledgeGraph(mission.name, Storage(tmp_path))
    event_bus = EventBus()
    event_bus.publish(
        "ai_decision_result",
        {
            "type": "ai_decision_result",
            "backend": "council",
            "council_arbiter": "arbiter",
            "phase": "DISCOVERY",
            "has_recommendation": True,
            "recommended_tool": "nmap",
            "recommended_target": "10.0.0.5",
            "recommendation_confidence": 0.8,
            "recommendation_reasoning": "evidence supports scan",
            "council": {
                "arbiter": "arbiter",
                "roles": {
                    "proposer": {"tool": "nmap", "target": "10.0.0.5", "confidence": 0.8},
                    "critic": {"tool": "http", "target": "10.0.0.5", "confidence": 0.5},
                    "verifier": {"tool": "nmap", "target": "10.0.0.5", "confidence": 0.8, "agrees_with_arbiter": True},
                },
                "consensus": {"agreement_count": 2, "eligible_votes": 3, "is_unanimous": False, "is_split_vote": True},
            },
        },
        trace_id="operator-trace",
    )
    event_bus.publish(
        "decision",
        {
            "type": "decision",
            "phase": "DISCOVERY",
            "decision_source": "advisor",
            "action": {"tool": "nmap", "target": "10.0.0.5"},
            "council": {"arbiter": "arbiter", "roles": {"proposer": "gpt", "arbiter": "gpt"}},
        },
        trace_id="operator-trace",
    )
    event_bus.publish(
        "approval_required",
        {"type": "approval_required", "tool": "nmap", "target": "10.0.0.5", "phase": "DISCOVERY"},
        trace_id="operator-trace",
    )
    app = create_app(
        secret="secret",
        users={
            "alice": {"password": "pw1", "role": "analyst"},
            "bob": {"password": "pw2", "role": "approver"},
            "carol": {"password": "pw3", "role": "observer"},
        },
        data_dir=tmp_path,
        mission=mission,
        graph=graph,
        event_bus=event_bus,
        artifact_router=artifact_router,
    )
    client = app.test_client()

    analyst_login = client.post("/auth/login", json={"username": "alice", "password": "pw1", "mission_id": "m1"})
    approver_login = client.post("/auth/login", json={"username": "bob", "password": "pw2", "mission_id": "m1"})
    observer_login = client.post("/auth/login", json={"username": "carol", "password": "pw3", "mission_id": "m1"})

    analyst_token = analyst_login.get_json()["token"]
    approver_token = approver_login.get_json()["token"]
    observer_token = observer_login.get_json()["token"]
    analyst_session_id = analyst_login.get_json()["session"]["session_id"]

    approval = client.post(
        "/approvals",
        json={"action": {"tool": "nmap", "target": "10.0.0.5"}},
        headers=_auth_header(analyst_token),
    )
    approval_id = approval.get_json()["approval_id"]

    observer_decision = client.post(
        f"/approvals/{approval_id}/decision",
        json={"decision": "approve"},
        headers=_auth_header(observer_token),
    )
    assert observer_decision.status_code == 403

    approver_decision = client.post(
        f"/approvals/{approval_id}/decision",
        json={"decision": "approve"},
        headers=_auth_header(approver_token),
    )
    assert approver_decision.status_code == 200
    assert approver_decision.get_json()["decision"] == "approve"

    own_session = client.get(f"/sessions/{analyst_session_id}", headers=_auth_header(analyst_token))
    assert own_session.status_code == 200

    foreign_session = client.get(f"/sessions/{analyst_session_id}", headers=_auth_header(observer_token))
    assert foreign_session.status_code == 403

    mission_current = client.get("/missions/current", headers=_auth_header(observer_token))
    assert mission_current.status_code == 200
    assert mission_current.get_json()["council"]["last_arbiter"] == "arbiter"
    assert mission_current.get_json()["council"]["accepted_count"] == 1
    assert mission_current.get_json()["council"]["role_breakdown"][0]["role"] == "verifier"
    assert mission_current.get_json()["council"]["recent_rounds"][0]["outcome"] == "accepted"
    assert mission_current.get_json()["council"]["recommendation_drift_count"] == 0
    assert mission_current.get_json()["council"]["current_override_streak"] == 0

    live_stream = client.get("/missions/current/live-stream", headers=_auth_header(observer_token))
    assert live_stream.status_code == 200
    assert "completed split arbitration" in live_stream.get_json()["items"][0]["narrative"]
    assert live_stream.get_json()["items"][2]["priority"] == "high"
    assert "Review and approve or deny" in live_stream.get_json()["items"][2]["operator_action"]

    reports = client.get("/reports", headers=_auth_header(analyst_token))
    assert reports.status_code == 200
    download_url = reports.get_json()["items"][0]["download_url"]
    download = client.get(download_url, headers=_auth_header(analyst_token))
    assert download.status_code == 200
    assert download.get_json()["ok"] is True
