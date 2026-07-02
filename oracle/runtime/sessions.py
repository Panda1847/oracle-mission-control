"""
ORACLE — Session Manager  (runtime/sessions.py)
Manages persistent PTY shell sessions via pexpect.
Allows multiple commands to run in the same terminal state.
"""
from __future__ import annotations
import logging
import threading
import time
import os
import select
import signal
import shlex
import subprocess
import pty
from typing import Dict, Optional, Tuple

log = logging.getLogger("oracle.sessions")
from .go_client import GoRuntimeClient


class SessionManager:
    """
    Named PTY sessions that persist across commands.

    Usage:
        sm = SessionManager()
        out, rc = sm.run("my_shell", "id")
        out, rc = sm.run("my_shell", "whoami")   # same session
        sm.close("my_shell")
    """

    def __init__(self):
        self._sessions: Dict[str, object] = {}
        self._lock = threading.Lock()
        self._current_pid = None
        self._runtime = GoRuntimeClient()
        self._unsafe_tokens = {"|", "||", ";", "&&", ">", ">>", "<", "<<", "2>", "&>", "2>&1"}

    def _normalize_command(self, cmd: str) -> tuple[list[str] | None, str]:
        if not cmd or not cmd.strip():
            return None, "empty command"
        if "\n" in cmd or "\r" in cmd:
            return None, "multi-line command not allowed"
        for meta in ("`", "$(", "${"):
            if meta in cmd:
                return None, f"unsafe interpolation token: {meta}"
        try:
            argv = shlex.split(cmd)
        except ValueError as exc:
            return None, f"parse error: {exc}"
        if not argv:
            return None, "empty argv"
        for token in argv:
            if token in self._unsafe_tokens:
                return None, f"shell control token not allowed: {token}"
        return argv, ""

    def run(self, session_id: str, command: str,
            expect: str = r"[\$#>] ",
            timeout: int = 30) -> Tuple[str, int]:
        """
        Send command to a named session and wait for prompt.
        Creates a bash session if one doesn't exist.
        """
        if self._runtime.ensure_started():
            try:
                response = self._runtime.session_run(session_id, command, timeout)
                return response.get("output", ""), int(response.get("returncode", -1))
            except Exception as e:
                log.warning("Go runtime session failed, falling back to pexpect: %s", e)
        try:
            import pexpect
        except ImportError:
            return "[pexpect not installed] pip install pexpect", -1

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not session.isalive():
                try:
                    session = pexpect.spawn(
                        "/bin/bash", encoding="utf-8", timeout=timeout
                    )
                    session.expect(r"[\$#] ", timeout=10)
                    self._sessions[session_id] = session
                    log.debug("New PTY session: %s", session_id)
                except Exception as e:
                    return f"[PTY Error] {e}", -1

        try:
            session.sendline(command)
            session.expect(expect, timeout=timeout)
            return (session.before or "").strip(), 0
        except Exception as e:
            buf = getattr(session, "before", "") or ""
            return f"[{type(e).__name__}] {buf[:500]}", -1

    def reset(self):
        if self._current_pid:
            try:
                os.killpg(os.getpgid(self._current_pid), signal.SIGKILL)
            except OSError:
                pass
            self._current_pid = None

    def execute(self, cmd: str, timeout: int = 300) -> str:
        if self._runtime.ensure_started():
            try:
                response = self._runtime.execute(command=cmd, timeout_seconds=timeout)
                return (response.get("stdout", "") or "") + (response.get("stderr", "") or "")
            except Exception as e:
                log.warning("Go runtime execute failed, falling back to local PTY: %s", e)
        argv, err = self._normalize_command(cmd)
        if argv is None:
            raise ValueError(f"unsafe command rejected: {err}")
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            argv,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            preexec_fn=os.setsid   # NEW PROCESS GROUP
        )
        os.close(slave_fd)
        self._current_pid = proc.pid
        output = b""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                self.reset()
                os.close(master_fd)
                raise TimeoutError(f"Tool timed out after {timeout}s: {cmd}")
            r, _, _ = select.select([master_fd], [], [], min(remaining, 5))
            if r:
                try:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    output += chunk
                except OSError:
                    break
            elif proc.poll() is not None:
                break
        proc.wait()
        os.close(master_fd)
        self._current_pid = None
        return output.decode(errors="replace")

    def active(self) -> Dict[str, bool]:
        if self._runtime.ensure_started():
            try:
                response = self._runtime.session_active()
                sessions = response.get("sessions", {})
                if isinstance(sessions, dict):
                    return {str(k): bool(v) for k, v in sessions.items()}
            except Exception as e:
                log.warning("Go runtime active query failed, falling back locally: %s", e)
        return {sid: s.isalive() for sid, s in self._sessions.items()}

    def close(self, session_id: str) -> bool:
        if self._runtime.ensure_started():
            try:
                response = self._runtime.session_close(session_id)
                return bool(response.get("closed", False))
            except Exception as e:
                log.warning("Go runtime close failed, falling back locally: %s", e)
        with self._lock:
            s = self._sessions.pop(session_id, None)
            if s:
                try:
                    s.close(force=True)
                except Exception:
                    pass
                return True
        return False

    def close_all(self):
        with self._lock:
            for s in self._sessions.values():
                try:
                    s.close(force=True)
                except Exception:
                    pass
            self._sessions.clear()
