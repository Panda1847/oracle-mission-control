"""
ORACLE — Executor  (runtime/executor.py)
Builds shell commands from Action objects and executes them safely.
"""
from __future__ import annotations
import hashlib
import logging
import os
import shlex
import shutil
import signal
import subprocess
import time
from threading import RLock
from typing import Optional

from ..core.models import Action, ActionResult
from ..plugins.base import PluginRegistry
from plugins.result_validator import GLOBAL_PLUGIN_RESULT_VALIDATOR
from .go_client import GoRuntimeClient

log = logging.getLogger("oracle.executor")


class Executor:
    """
    Builds the command string via the plugin registry, then runs it
    in a subprocess with timeout protection.
    """

    def __init__(self, registry: PluginRegistry, runtime_client: Optional[GoRuntimeClient] = None):
        self.registry = registry
        self.runtime_client = runtime_client or GoRuntimeClient()
        self._running: dict[int, subprocess.Popen] = {}
        self._lock = RLock()
        self._prefer_go_runtime = os.environ.get("ORACLE_EXECUTOR_USE_GO_RUNTIME", "").lower() in {"1", "true", "yes"}

    SHELL_META_TOKENS = {"|", "||", ";", "&&", ">", ">>", "<", "<<", "2>", "&>", "2>&1"}

    def _fingerprint(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _normalize_command(self, cmd: str) -> tuple[list[str] | None, str]:
        if not cmd or not cmd.strip():
            return None, "empty command"
        if "\n" in cmd or "\r" in cmd:
            return None, "multi-line command not allowed"
        for meta in ("`", "$(", "${"):
            if meta in cmd:
                return None, f"unsafe shell interpolation token found: {meta}"
        try:
            argv = shlex.split(cmd)
        except ValueError as exc:
            return None, f"command parse error: {exc}"
        if not argv:
            return None, "empty command argv"
        for token in argv:
            if token in self.SHELL_META_TOKENS:
                return None, f"shell control token not allowed: {token}"
        return argv, ""

    def _missing_binary(self, argv: list[str]) -> tuple[bool, str]:
        binary = argv[0]
        if os.path.isabs(binary) and os.access(binary, os.X_OK):
            return False, ""
        if shutil.which(binary):
            return False, ""
        return True, binary

    def terminate_all(self):
        with self._lock:
            processes = list(self._running.values())
            self._running.clear()
        for proc in processes:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def build_command(self, action: Action) -> str:
        """Return the shell command string for a given action (without running it)."""
        plugin = self.registry.get(action.tool)
        if not plugin:
            return f"echo 'Unknown tool: {action.tool}'"
        try:
            return plugin.build(action.target, action.args)
        except Exception as e:
            return f"echo 'Plugin build error: {type(e).__name__}: {e}'"

    def run(self, action: Action) -> ActionResult:
        """Execute the action and return a structured result."""
        plugin = self.registry.get(action.tool)
        if not plugin:
            return ActionResult(action, "", f"Unknown tool: {action.tool}", -1, 0, error_kind="plugin_unavailable")

        try:
            cmd = plugin.build(action.target, action.args)
        except Exception as e:
            return ActionResult(action, "", f"Plugin build error: {type(e).__name__}: {e}", -1, 0, error_kind="plugin_build_error")
        if not cmd.strip():
            return ActionResult(action, "", "Plugin returned empty command", -1, 0, error_kind="empty_command")

        log.debug("Running [%s]: %s", action.tool, cmd[:200])
        argv, normalize_error = self._normalize_command(cmd)
        if argv is None:
            return ActionResult(
                action,
                "",
                normalize_error,
                -1,
                0,
                parse_valid=False,
                quarantined=True,
                error_kind="unsafe_command",
                command_fingerprint=self._fingerprint(cmd),
            )

        missing, binary = self._missing_binary(argv)
        if missing:
            return ActionResult(
                action,
                "",
                f"Missing binary: {binary}",
                127,
                0,
                binary_missing=True,
                error_kind="binary_missing",
                command_fingerprint=self._fingerprint(cmd),
            )

        execution = self.execute_command(cmd, argv, action.timeout)
        return self.build_action_result(
            action,
            cmd,
            execution["stdout"],
            execution["stderr"],
            execution["returncode"],
            execution["duration"],
            timeout_hit=execution["timeout_hit"],
            binary_missing=execution["binary_missing"],
            error_kind=execution["error_kind"],
        )

    def build_action_result(
        self,
        action: Action,
        cmd: str,
        stdout: str,
        stderr: str,
        rc: int,
        duration: float,
        timeout_hit: bool = False,
        binary_missing: bool = False,
        error_kind: str = "",
        worker_id: str = "local-node",
    ) -> ActionResult:
        plugin = self.registry.get(action.tool)
        if not plugin:
            return ActionResult(
                action,
                stdout,
                stderr,
                rc,
                duration,
                parsed={"_cmd": cmd, "_target": action.target, "_worker_id": worker_id},
                timeout_hit=timeout_hit,
                binary_missing=binary_missing,
                parse_valid=False,
                quarantined=True,
                error_kind=error_kind or "plugin_unavailable",
                command_fingerprint=self._fingerprint(cmd),
            )

        # Let plugin parse the output
        parse_error = ""
        try:
            parsed = plugin.parse(stdout, stderr) or {}
            if not isinstance(parsed, dict):
                parsed = {"raw": str(parsed)[:3000]}
            if "status" not in parsed or "data" not in parsed:
                parsed = {"status": "ok", "data": dict(parsed), "error": ""}
            # Compatibility bridge: expose parsed data keys at top-level for legacy readers.
            data_block = parsed.get("data")
            if isinstance(data_block, dict):
                for key, value in data_block.items():
                    parsed.setdefault(key, value)
        except Exception as e:
            parse_error = f"{type(e).__name__}: {e}"
            parsed = {"status": "error", "data": {}, "error": f"parse_error:{parse_error}"}

        validation = GLOBAL_PLUGIN_RESULT_VALIDATOR.validate(action.tool, parsed, target=action.target)
        parsed = validation.parsed
        parsed["_target"] = action.target
        parsed["_cmd"] = cmd
        parsed["_worker_id"] = worker_id
        parsed["_command_fingerprint"] = self._fingerprint(cmd)
        parsed["_parse_repaired"] = validation.repaired
        if parse_error:
            parsed["_parse_exception"] = parse_error
            parsed["parse_error"] = parse_error

        parse_valid = validation.valid and parsed.get("status") != "error"
        quarantined = not parse_valid or bool(parsed.get("quarantined"))

        ar = ActionResult(
            action=action,
            stdout=stdout,
            stderr=stderr,
            returncode=rc,
            duration=duration,
            parsed=parsed,
            timeout_hit=timeout_hit,
            binary_missing=binary_missing,
            parse_valid=parse_valid,
            quarantined=quarantined,
            error_kind=error_kind or ("parse_contract" if not parse_valid else ""),
            command_fingerprint=self._fingerprint(cmd),
        )
        log.debug("Result: rc=%d, %.1fs, %d bytes out", rc, duration, len(stdout))
        return ar

    def execute_command(self, cmd: str, argv: list[str], timeout: int) -> dict[str, object]:
        if self._prefer_go_runtime and self.runtime_client.ensure_started():
            try:
                response = self.runtime_client.execute(
                    command=cmd,
                    timeout_seconds=timeout,
                )
                return {
                    "stdout": response.get("stdout", "") or "",
                    "stderr": response.get("stderr", "") or "",
                    "returncode": int(response.get("returncode", -1)),
                    "duration": float(response.get("duration_ms", 0)) / 1000.0,
                    "timeout_hit": bool(response.get("timed_out", False)),
                    "binary_missing": False,
                    "error_kind": "timeout" if bool(response.get("timed_out", False)) else "",
                }
            except Exception as e:
                log.warning("Go runtime execution failed, falling back to local subprocess: %s", e)

        start = time.time()
        proc: subprocess.Popen | None = None
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            with self._lock:
                self._running[proc.pid] = proc
            stdout, stderr = proc.communicate(timeout=timeout)
            return {
                "stdout": stdout or "",
                "stderr": stderr or "",
                "returncode": int(proc.returncode or 0),
                "duration": time.time() - start,
                "timeout_hit": False,
                "binary_missing": False,
                "error_kind": "",
            }
        except subprocess.TimeoutExpired:
            log.warning("Timeout: command exceeded %ss", timeout)
            if proc is not None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except Exception:
                    stdout, stderr = "", ""
            else:
                stdout, stderr = "", ""
            return {
                "stdout": stdout or "",
                "stderr": (stderr or "") + ("" if stderr else f"[TIMEOUT] Command exceeded {timeout}s"),
                "returncode": -1,
                "duration": time.time() - start,
                "timeout_hit": True,
                "binary_missing": False,
                "error_kind": "timeout",
            }
        except FileNotFoundError as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 127,
                "duration": time.time() - start,
                "timeout_hit": False,
                "binary_missing": True,
                "error_kind": "binary_missing",
            }
        except Exception as e:
            log.error("Executor error: %s", e)
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "duration": time.time() - start,
                "timeout_hit": False,
                "binary_missing": False,
                "error_kind": "execution_error",
            }
        finally:
            if proc is not None:
                with self._lock:
                    self._running.pop(proc.pid, None)
