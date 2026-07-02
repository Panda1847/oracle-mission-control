"""SOC-grade dashboard backend gateway and static frontend server."""

from __future__ import annotations

import base64
from collections import defaultdict, deque
import json
import threading
import time
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from api.evidence import evidence_snapshot
from api.missions import mission_snapshot, mission_timeline
from api.plugins import plugin_snapshot
from api.reports import report_snapshot
from dashboard.live_stream import build_live_stream
from api.workers import worker_snapshot
from telemetry.health import GLOBAL_HEALTH
from telemetry.metrics import GLOBAL_METRICS
from telemetry.tracing import GLOBAL_TRACES


def _frontend_dir() -> Path:
    return Path(__file__).resolve().parent / "frontend"


def create_gateway(
    *,
    mission=None,
    graph=None,
    dispatcher=None,
    plugin_registry=None,
    event_bus=None,
    approvals=None,
    artifact_router=None,
    metrics=None,
    health=None,
    tracer=None,
    auth_token: str = "",
    auth_user: str = "",
    auth_pass: str = "",
):
    app = Flask(__name__, static_folder=str(_frontend_dir()), static_url_path="/assets")
    metrics = metrics or GLOBAL_METRICS
    health = health or GLOBAL_HEALTH
    tracer = tracer or GLOBAL_TRACES
    auth_token = str(auth_token or "").strip()
    auth_user = str(auth_user or "").strip()
    auth_pass = str(auth_pass or "")
    rate_windows = {
        "default": {"max_requests": 180, "window_seconds": 60},
        "/api/dashboard/export": {"max_requests": 20, "window_seconds": 60},
    }
    request_buckets: dict[str, deque[float]] = defaultdict(deque)
    rate_lock = threading.RLock()

    def _client_addr() -> str:
        forwarded = (request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
        remote = forwarded or (request.remote_addr or "")
        return remote.strip().lower()

    def _is_loopback_client() -> bool:
        client = _client_addr()
        return client in {"127.0.0.1", "::1", "localhost"} or client.startswith("::ffff:127.0.0.1")

    def _enforce_rate_limit():
        if not request.path.startswith("/api/dashboard/"):
            return None
        policy = rate_windows.get(request.path, rate_windows["default"])
        now = time.monotonic()
        key = f"{_client_addr()}::{request.path}"
        with rate_lock:
            bucket = request_buckets[key]
            cutoff = now - float(policy["window_seconds"])
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= int(policy["max_requests"]):
                return jsonify({"error": "rate_limited"}), 429
            bucket.append(now)
        return None

    def _authed() -> bool:
        # Token auth via header.
        if auth_token:
            provided = (request.headers.get("X-Oracle-Token") or "").strip()
            if not provided:
                provided = (request.cookies.get("oracle_token") or "").strip()
            return bool(provided) and provided == auth_token
        # Basic auth via Authorization header.
        if auth_user and auth_pass:
            header = request.headers.get("Authorization") or ""
            if not header.startswith("Basic "):
                return False
            try:
                raw = base64.b64decode(header.split(" ", 1)[1].strip()).decode("utf-8", errors="replace")
            except Exception:
                return False
            if ":" not in raw:
                return False
            user, pw = raw.split(":", 1)
            return user == auth_user and pw == auth_pass
        # Secure default: if no credentials configured, only loopback clients are allowed.
        return _is_loopback_client()

    def _require_auth():
        rate_error = _enforce_rate_limit()
        if rate_error is not None:
            return rate_error
        if _authed():
            return None
        hint = "Use --web-auth-token or --web-auth-user/--web-auth-pass when exposing dashboard outside localhost."
        return jsonify({"error": "unauthorized", "hint": hint}), 401

    @app.get("/")
    def index():
        response = send_from_directory(_frontend_dir(), "index.html")
        token_query = (request.args.get("token") or "").strip()
        if auth_token and token_query and token_query == auth_token:
            response.set_cookie("oracle_token", auth_token, httponly=True, samesite="Lax")
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify(health.summary())

    @app.get("/api/dashboard/overview")
    def overview():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify(mission_snapshot(mission, graph, event_bus=event_bus, plugin_registry=plugin_registry))

    @app.get("/api/dashboard/timeline")
    def timeline():
        auth = _require_auth()
        if auth is not None:
            return auth
        limit = int(request.args.get("limit", 200) or 200)
        return jsonify({"items": mission_timeline(mission, graph, event_bus=event_bus, limit=limit)})

    @app.get("/api/dashboard/live-stream")
    def live_stream():
        auth = _require_auth()
        if auth is not None:
            return auth
        limit = int(request.args.get("limit", 200) or 200)
        return jsonify(build_live_stream(mission=mission, graph=graph, event_bus=event_bus, limit=limit))

    @app.get("/api/dashboard/workers")
    def workers():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify({"items": worker_snapshot(dispatcher)})

    @app.get("/api/dashboard/plugins")
    def plugins():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify({"items": plugin_snapshot(plugin_registry)})

    @app.get("/api/dashboard/evidence")
    def evidence():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify(evidence_snapshot(graph))

    @app.get("/api/dashboard/telemetry")
    def telemetry():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify(
            {
                "metrics": metrics.snapshot(),
                "health": health.summary(),
                "traces": tracer.snapshot(),
            }
        )

    @app.get("/api/dashboard/artifacts")
    def artifacts():
        auth = _require_auth()
        if auth is not None:
            return auth
        return jsonify({"items": report_snapshot(artifact_router, download_prefix="/api/dashboard/artifacts/download")})

    @app.get("/api/dashboard/artifacts/download/<path:artifact_path>")
    def artifact_download(artifact_path: str):
        auth = _require_auth()
        if auth is not None:
            return auth
        if artifact_router is None:
            return jsonify({"error": "artifact router unavailable"}), 503
        resolved = artifact_router.resolve(artifact_path)
        if resolved is None:
            abort(404)
        return send_file(resolved, as_attachment=True, download_name=resolved.name)

    @app.get("/api/dashboard/approvals")
    def approval_items():
        auth = _require_auth()
        if auth is not None:
            return auth
        if approvals is None:
            return jsonify({"items": []})
        return jsonify({"items": approvals.pending()})

    @app.get("/api/dashboard/chat")
    def chat_history():
        auth = _require_auth()
        if auth is not None:
            return auth
        if graph is None:
            return jsonify({"messages": []})
        return jsonify({"messages": graph.recent_chat(100)})

    @app.post("/api/dashboard/chat")
    def post_chat():
        auth = _require_auth()
        if auth is not None:
            return auth
        if graph is None:
            return jsonify({"error": "graph unavailable"}), 503
        payload = request.get_json() or {}
        message = graph.add_chat_message(
            user=str(payload.get("user", "operator")),
            text=str(payload.get("text", "")),
            ts=str(payload.get("ts", "")),
        )
        return jsonify(message), 201

    @app.post("/api/dashboard/directives")
    def post_directive():
        auth = _require_auth()
        if auth is not None:
            return auth
        if graph is None:
            return jsonify({"error": "graph unavailable"}), 503
        payload = request.get_json() or {}
        text = str(payload.get("text", "")).strip()
        if not text:
            return jsonify({"error": "text is required"}), 400
        graph.add_directive(text)
        return jsonify({"ok": True, "text": text}), 201

    @app.get("/api/dashboard/export")
    def export_snapshot():
        auth = _require_auth()
        if auth is not None:
            return auth
        snapshot = {
            "overview": mission_snapshot(mission, graph, event_bus=event_bus, plugin_registry=plugin_registry),
            "timeline": mission_timeline(mission, graph, event_bus=event_bus, limit=500),
            "live_stream": build_live_stream(mission=mission, graph=graph, event_bus=event_bus, limit=500),
            "workers": worker_snapshot(dispatcher),
            "plugins": plugin_snapshot(plugin_registry),
            "evidence": evidence_snapshot(graph),
            "artifacts": report_snapshot(artifact_router, download_prefix="/api/dashboard/artifacts/download"),
        }
        return app.response_class(json.dumps(snapshot, sort_keys=True), mimetype="application/json")

    return app


def run_gateway(
    graph,
    mission,
    *,
    dispatcher=None,
    plugin_registry=None,
    event_bus=None,
    approvals=None,
    artifact_router=None,
    port: int = 5000,
):
    app = create_gateway(
        mission=mission,
        graph=graph,
        dispatcher=dispatcher,
        plugin_registry=plugin_registry,
        event_bus=event_bus,
        approvals=approvals,
        artifact_router=artifact_router,
    )
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
