"""Master-side callback server for async worker results."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

from .auth import WorkerAuth


class ResultCallbackServer:
    """Receives asynchronous worker job results."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, shared_secret: str = ""):
        self.host = host
        self.port = port
        self.auth = WorkerAuth(shared_secret)
        self._events: Dict[str, threading.Event] = {}
        self._results: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def callback_url(self) -> str:
        if not self._server:
            raise RuntimeError("callback server not started")
        return f"http://{self.host}:{self._server.server_port}/callback"

    def start(self):
        if self._server:
            return
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if self.path != "/callback" or not outer.auth.verify(data, self.headers):
                    self.send_response(403)
                    self.end_headers()
                    return
                job_id = str(data.get("job_id", ""))
                if not job_id:
                    self.send_response(400)
                    self.end_headers()
                    return
                outer._store(job_id, data)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, _fmt, *_args):
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
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

    def wait_for(self, job_id: str, timeout: float) -> Optional[dict]:
        with self._lock:
            event = self._events.setdefault(job_id, threading.Event())
        if not event.wait(timeout):
            return None
        with self._lock:
            return self._results.get(job_id)

    def _store(self, job_id: str, payload: dict):
        with self._lock:
            self._results[job_id] = payload
            event = self._events.setdefault(job_id, threading.Event())
            event.set()
