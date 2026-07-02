"""Operator control API with RBAC, session ownership, and approvals."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file

from .approvals import ApprovalQueue
from .evidence import evidence_snapshot
from .auth import AuthService, OperatorIdentity
from .missions import mission_snapshot, mission_timeline
from .plugins import plugin_snapshot
from .reports import report_snapshot
from .workers import worker_snapshot
from dashboard.live_stream import build_live_stream
from security.audit_chain import ActorAuditChain
from storage.sessions import OperatorSessionStore
from telemetry.health import GLOBAL_HEALTH
from telemetry.metrics import GLOBAL_METRICS
from telemetry.tracing import GLOBAL_TRACES


def create_app(
    *,
    secret: str = "oracle-enterprise-secret",
    users: dict[str, dict[str, str]] | None = None,
    data_dir: Path | None = None,
    mission=None,
    graph=None,
    dispatcher=None,
    plugin_registry=None,
    event_bus=None,
    artifact_router=None,
    approvals: ApprovalQueue | None = None,
):
    app = Flask(__name__)
    base_dir = Path(data_dir or Path.cwd() / ".oracle-api")
    sessions = OperatorSessionStore(base_dir / "sessions.json")
    approvals = approvals or ApprovalQueue()
    auth = AuthService(secret, users=users or {})
    audit = ActorAuditChain(base_dir / "actor_audit.jsonl")

    def current_identity() -> OperatorIdentity:
        header = (request.headers.get("Authorization") or "").strip()
        if not header.lower().startswith("bearer "):
            raise PermissionError("missing bearer token")
        token = header.split(None, 1)[1].strip()
        return auth.verify_token(token)

    @app.errorhandler(PermissionError)
    def _permission_error(exc):
        return jsonify({"error": str(exc)}), 403

    @app.post("/auth/login")
    def login():
        payload = request.get_json() or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        mission_id = str(payload.get("mission_id", "default"))
        user = (users or {}).get(username)
        if not user or not auth.authenticate(username, password):
            return jsonify({"error": "invalid credentials"}), 401
        session = sessions.create(username=username, role=user["role"], mission_id=mission_id)
        identity = OperatorIdentity(username=username, role=user["role"], session_id=session.session_id, mission_id=mission_id)
        token = auth.issue_token(identity)
        audit.log("login", username, user["role"], session.session_id, {"mission_id": mission_id})
        return jsonify({"token": token, "session": asdict(session)})

    @app.get("/auth/me")
    def me():
        identity = current_identity()
        session = sessions.get(identity.session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        return jsonify({"identity": asdict(identity), "session": asdict(session)})

    @app.get("/health")
    def health():
        return jsonify(
            {
                "health": GLOBAL_HEALTH.summary(),
                "metrics": GLOBAL_METRICS.snapshot(),
                "traces": GLOBAL_TRACES.snapshot(),
            }
        )

    @app.post("/approvals")
    def create_approval():
        identity = current_identity()
        if not auth.has_permission(identity.role, "operate"):
            raise PermissionError("operator role cannot request approvals")
        payload = request.get_json() or {}
        request_obj = approvals.submit(
            requested_by=identity.username,
            requested_role=identity.role,
            mission_id=identity.mission_id,
            action=dict(payload.get("action") or {}),
        )
        audit.log("approval_requested", identity.username, identity.role, identity.session_id, {"approval_id": request_obj.approval_id})
        return jsonify(asdict(request_obj)), 201

    @app.post("/approvals/<approval_id>/decision")
    def decide_approval(approval_id: str):
        identity = current_identity()
        if not auth.has_permission(identity.role, "approve"):
            raise PermissionError("approval decision requires approver role")
        payload = request.get_json() or {}
        decision = str(payload.get("decision", ""))
        request_obj = approvals.decide(approval_id, actor=identity.username, decision=decision)
        audit.log("approval_decided", identity.username, identity.role, identity.session_id, {"approval_id": approval_id, "decision": decision})
        return jsonify(asdict(request_obj))

    @app.get("/approvals/pending")
    def pending_approvals():
        identity = current_identity()
        if not auth.has_permission(identity.role, "approve") and not auth.has_permission(identity.role, "audit"):
            raise PermissionError("viewing approval queue requires approver or auditor role")
        return jsonify({"items": approvals.pending()})

    @app.get("/sessions/<session_id>")
    def session_info(session_id: str):
        identity = current_identity()
        session = sessions.get(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        if identity.username != session.username and identity.role not in {"admin", "auditor"}:
            raise PermissionError("session ownership required")
        return jsonify({"session": asdict(session)})

    @app.get("/missions/current")
    def current_mission():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        return jsonify(mission_snapshot(mission, graph, event_bus=event_bus, plugin_registry=plugin_registry))

    @app.get("/missions/current/timeline")
    def current_timeline():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        limit = int(request.args.get("limit", 200) or 200)
        return jsonify({"items": mission_timeline(mission, graph, event_bus=event_bus, limit=limit)})

    @app.get("/missions/current/live-stream")
    def current_live_stream():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        limit = int(request.args.get("limit", 200) or 200)
        return jsonify(build_live_stream(mission=mission, graph=graph, event_bus=event_bus, limit=limit))

    @app.get("/workers")
    def workers():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        return jsonify({"items": worker_snapshot(dispatcher)})

    @app.get("/plugins")
    def plugins():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        return jsonify({"items": plugin_snapshot(plugin_registry)})

    @app.get("/evidence")
    def evidence():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        return jsonify(evidence_snapshot(graph))

    @app.get("/reports")
    def reports():
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        return jsonify({"items": report_snapshot(artifact_router, download_prefix="/reports/download")})

    @app.get("/reports/download/<path:artifact_path>")
    def report_download(artifact_path: str):
        identity = current_identity()
        if not auth.has_permission(identity.role, "observe"):
            raise PermissionError("observe permission required")
        if artifact_router is None:
            return jsonify({"error": "artifact router unavailable"}), 503
        resolved = artifact_router.resolve(artifact_path)
        if resolved is None:
            abort(404)
        return send_file(resolved, as_attachment=True, download_name=resolved.name)

    return app
