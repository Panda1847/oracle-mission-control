"""HTTP worker node that accepts jobs and posts results back to the master."""

from __future__ import annotations

import json
import subprocess
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
from typing import Optional
from uuid import uuid4

from oracle.runtime.go_client import GoRuntimeClient

from .auth import WorkerAuth


class WorkerAgent:
    """Remote worker HTTP server."""

    def __init__(
        self,
        worker_id: str,
        capabilities: list[str],
        shared_secret: str = "",
        host: str = "127.0.0.1",
        port: int = 0,
        tls_certfile: str = "",
        tls_keyfile: str = "",
        tls_ca_file: str = "",
        require_client_cert: bool = False,
    ):
        self.worker_id = worker_id
        self.capabilities = list(capabilities or ["*"])
        self.auth = WorkerAuth(shared_secret)
        self.host = host
        self.port = port
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile
        self.tls_ca_file = tls_ca_file
        self.require_client_cert = require_client_cert
        self.runtime = GoRuntimeClient()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def endpoint(self) -> str:
        if not self._server:
            raise RuntimeError("worker agent not started")
        return f"http://{self.host}:{self._server.server_port}"

    def start(self):
        if self._server:
            return
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/health":
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = {
                    "worker_id": outer.worker_id,
                    "capabilities": outer.capabilities,
                    "status": "ok",
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode("utf-8"))

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if self.path != "/jobs" or not outer.auth.verify(payload, self.headers):
                    self.send_response(403)
                    self.end_headers()
                    return
                job_id = str(payload.get("job_id") or uuid4().hex)
                callback_url = str(payload.get("callback_url", ""))
                threading.Thread(
                    target=outer._execute_and_callback,
                    args=(job_id, payload, callback_url),
                    daemon=True,
                ).start()
                response = {"accepted": True, "job_id": job_id, "worker_id": outer.worker_id}
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))

            def log_message(self, _fmt, *_args):
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        if self.tls_certfile and self.tls_keyfile:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.tls_certfile, keyfile=self.tls_keyfile)
            if self.tls_ca_file:
                context.load_verify_locations(cafile=self.tls_ca_file)
            if self.require_client_cert:
                context.verify_mode = ssl.CERT_REQUIRED
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _execute_and_callback(self, job_id: str, payload: dict, callback_url: str):
        command = str(payload.get("command", ""))
        timeout_seconds = int(payload.get("timeout_seconds", 60) or 60)
        try:
            if self.runtime.ensure_started():
                response = self.runtime.execute(command=command, timeout_seconds=timeout_seconds)
            else:
                response = self._fallback_execute(command, timeout_seconds, "go_runtime_unavailable")
        except Exception as exc:
            response = self._fallback_execute(command, timeout_seconds, str(exc))
        callback_payload = {
            "job_id": job_id,
            "worker_id": self.worker_id,
            "stdout": response.get("stdout", ""),
            "stderr": response.get("stderr", ""),
            "returncode": int(response.get("returncode", -1)),
            "duration_ms": int(response.get("duration_ms", 0)),
            "timed_out": bool(response.get("timed_out", False)),
        }
        headers = {"Content-Type": "application/json", **self.auth.sign(callback_payload)}
        context = None
        if callback_url.startswith("https://") and self.tls_ca_file:
            context = ssl.create_default_context(cafile=self.tls_ca_file)
            if self.tls_certfile and self.tls_keyfile:
                context.load_cert_chain(certfile=self.tls_certfile, keyfile=self.tls_keyfile)
        req = urllib.request.Request(
            callback_url,
            data=json.dumps(callback_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=max(5, timeout_seconds), context=context):
                return
        except Exception:
            return

    def _fallback_execute(self, command: str, timeout_seconds: int, reason: str) -> dict:
        try:
            completed = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True,
                timeout=max(1, timeout_seconds),
            )
            return {
                "stdout": completed.stdout or "",
                "stderr": completed.stderr or "",
                "returncode": int(completed.returncode),
                "duration_ms": 0,
                "timed_out": False,
                "fallback_reason": reason,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "stdout": (exc.stdout or ""),
                "stderr": (exc.stderr or "") + "[TIMEOUT]",
                "returncode": -1,
                "duration_ms": 0,
                "timed_out": True,
                "fallback_reason": reason,
            }
        except Exception as exc:
            return {
                "stdout": "",
                "stderr": f"fallback execution error: {exc}",
                "returncode": -1,
                "duration_ms": 0,
                "timed_out": False,
                "fallback_reason": reason,
            }
