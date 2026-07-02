"""Client for the localhost Go execution runtime."""

from __future__ import annotations

import atexit
import json
import logging
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("oracle.go_runtime")


class GoRuntimeClient:
    """Builds, starts, and communicates with the Go runtime service."""

    def __init__(self, source_dir: Optional[Path] = None):
        self.root = Path(__file__).resolve().parents[2]
        self.source_dir = source_dir or (self.root / "runtime-go")
        self.bin_dir = Path.home() / ".oracle" / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.binary_path = self.bin_dir / "oracle-runtime-go"
        self.port = int(os.environ.get("ORACLE_GO_RUNTIME_PORT", "7778"))
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._proc: Optional[subprocess.Popen] = None
        self._disabled = os.environ.get("ORACLE_GO_RUNTIME_DISABLE", "").lower() in {"1", "true", "yes"}
        atexit.register(self.stop)

    def ensure_started(self) -> bool:
        if self._disabled:
            return False
        if self._healthy():
            return True
        try:
            self._build_binary()
            self._start_process()
            return self._wait_for_health()
        except Exception as exc:
            log.warning("go runtime unavailable: %s", exc)
            self.stop()
            return False

    def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None

    def execute(self, command: str, timeout_seconds: int, workdir: str = "", shell: str = "/bin/bash") -> Dict[str, Any]:
        payload = {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "workdir": workdir,
            "shell": shell,
        }
        return self._request("/execute", payload)

    def health(self) -> Dict[str, Any]:
        return self._request("/health", None, method="GET")

    def session_run(self, session_id: str, command: str, timeout_seconds: int, shell: str = "/bin/bash", workdir: str = "") -> Dict[str, Any]:
        payload = {
            "session_id": session_id,
            "command": command,
            "timeout_seconds": timeout_seconds,
            "shell": shell,
            "workdir": workdir,
        }
        return self._request("/session/run", payload)

    def session_close(self, session_id: str) -> Dict[str, Any]:
        return self._request("/session/close", {"session_id": session_id})

    def session_active(self) -> Dict[str, Any]:
        return self._request("/session/active", None, method="GET")

    def _request(self, path: str, payload: Optional[Dict[str, Any]], method: str = "POST") -> Dict[str, Any]:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _healthy(self) -> bool:
        try:
            data = self.health()
            return data.get("status") == "ok"
        except Exception:
            return False

    def _build_binary(self):
        if self.binary_path.exists() and self.binary_path.stat().st_mtime >= self._latest_source_mtime():
            return
        env = os.environ.copy()
        env.setdefault("CGO_ENABLED", "0")
        subprocess.run(
            ["go", "build", "-o", str(self.binary_path), "."],
            cwd=self.source_dir,
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )

    def _start_process(self):
        if self._proc and self._proc.poll() is None:
            return
        if self._port_in_use():
            return
        self._proc = subprocess.Popen(
            [str(self.binary_path), "-listen", f"127.0.0.1:{self.port}"],
            cwd=self.source_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _wait_for_health(self, timeout: float = 8.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._healthy():
                return True
            time.sleep(0.2)
        return False

    def _latest_source_mtime(self) -> float:
        latest = 0.0
        for path in self.source_dir.glob("*.go"):
            latest = max(latest, path.stat().st_mtime)
        go_mod = self.source_dir / "go.mod"
        if go_mod.exists():
            latest = max(latest, go_mod.stat().st_mtime)
        return latest

    def _port_in_use(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", self.port)) == 0
