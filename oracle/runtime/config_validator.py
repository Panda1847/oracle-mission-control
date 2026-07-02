"""Runtime configuration validator used by doctor and startup checks."""

from __future__ import annotations

import os
import socket
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from core.ai.model_router import ModelRouter
from workers.auth import WorkerAuth

from ..core.ai import OracleAI


@dataclass(frozen=True)
class RuntimeCheck:
    name: str
    detail: str
    ok: bool
    kind: str = "config"  # required | optional | config


def _as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class RuntimeConfigValidator:
    """Validates runtime preconditions without executing a mission."""

    def __init__(
        self,
        *,
        registry,
        data_dir: Path,
        log_dir: Path,
        config: Mapping[str, Any] | None = None,
        web_enabled: bool = False,
        web_auth_token: str = "",
        web_auth_user: str = "",
        web_auth_pass: str = "",
        env: Mapping[str, str] | None = None,
    ):
        self.registry = registry
        self.data_dir = Path(data_dir)
        self.log_dir = Path(log_dir)
        self.config = dict(config or {})
        self.web_enabled = bool(web_enabled)
        self.web_auth_token = str(web_auth_token or "")
        self.web_auth_user = str(web_auth_user or "")
        self.web_auth_pass = str(web_auth_pass or "")
        self.env = dict(env or os.environ)

    def _config_section(self, name: str) -> dict[str, Any]:
        primary = self.config.get(name, {})
        primary = dict(primary) if isinstance(primary, dict) else {}
        legacy = self.config.get("legacy", {})
        legacy = legacy if isinstance(legacy, dict) else {}
        legacy_section = legacy.get(name, {})
        legacy_section = dict(legacy_section) if isinstance(legacy_section, dict) else {}
        merged = dict(primary)
        merged.update(legacy_section)
        return merged

    def run(self) -> list[RuntimeCheck]:
        checks: list[RuntimeCheck] = []
        checks.extend(self._storage_checks())
        checks.append(self._binary_presence_check())
        checks.append(self._worker_secret_check())
        checks.append(self._auth_sanity_check())
        checks.append(self._dashboard_exposure_check())
        checks.append(self._ai_backend_check())
        checks.append(self._redis_check())
        return checks

    def _storage_checks(self) -> Iterable[RuntimeCheck]:
        checks: list[RuntimeCheck] = []
        for label, path in (("storage writable", self.data_dir), ("log writable", self.log_dir)):
            try:
                path.mkdir(parents=True, exist_ok=True)
                probe = path / ".oracle_write_probe"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                checks.append(RuntimeCheck(label, str(path), True, "required"))
            except Exception as exc:
                checks.append(RuntimeCheck(label, f"{path} ({exc})", False, "required"))
        return checks

    def _binary_presence_check(self) -> RuntimeCheck:
        available = dict(self.registry.available_map() if self.registry else {})
        missing = sorted([name for name, ok in available.items() if not ok])
        if missing:
            return RuntimeCheck(
                "binaries present",
                f"missing binaries for plugins: {', '.join(missing)}",
                False,
                "required",
            )
        return RuntimeCheck("binaries present", f"{len(available)} plugin binaries available", True, "required")

    def _worker_secret_check(self) -> RuntimeCheck:
        workers_cfg = self._config_section("workers")
        raw = workers_cfg.get("shared_secret", "")
        try:
            resolved = WorkerAuth.resolve_shared_secret(raw)
            return RuntimeCheck("worker secret sane", f"len={len(resolved)}", True, "required")
        except Exception as exc:
            return RuntimeCheck("worker secret sane", str(exc), False, "required")

    def _auth_sanity_check(self) -> RuntimeCheck:
        # Either token or full basic auth pair is sane.
        has_token = bool(self.web_auth_token)
        has_basic = bool(self.web_auth_user and self.web_auth_pass)
        half_basic = bool(self.web_auth_user) ^ bool(self.web_auth_pass)
        if half_basic:
            return RuntimeCheck("auth sane", "dashboard basic auth requires both user and pass", False, "required")
        if has_token or has_basic:
            return RuntimeCheck("auth sane", "dashboard auth credentials configured", True, "config")
        return RuntimeCheck("auth sane", "no explicit dashboard auth credentials provided", True, "config")

    def _dashboard_exposure_check(self) -> RuntimeCheck:
        if not self.web_enabled:
            return RuntimeCheck("dashboard exposure safe", "dashboard disabled", True, "config")
        has_token = bool(self.web_auth_token)
        has_basic = bool(self.web_auth_user and self.web_auth_pass)
        if has_token or has_basic:
            return RuntimeCheck("dashboard exposure safe", "dashboard auth enforced", True, "config")
        # Gateway blocks non-loopback access when no auth is configured.
        return RuntimeCheck(
            "dashboard exposure safe",
            "no auth set; relying on default non-loopback block in backend gateway",
            True,
            "config",
        )

    def _ai_backend_check(self) -> RuntimeCheck:
        router = ModelRouter(OracleAI())
        active = router.active()
        backend = str(getattr(router, "backend", "auto"))
        if backend == "deterministic":
            return RuntimeCheck("AI backend reachable", "deterministic backend selected", True, "config")
        if active is router.fallback():
            return RuntimeCheck("AI backend reachable", f"{backend} backend unavailable, fallback active", False, "config")
        return RuntimeCheck("AI backend reachable", f"{backend} backend active", True, "config")

    def _redis_check(self) -> RuntimeCheck:
        queue_cfg = self._config_section("queue")
        backend = str(queue_cfg.get("backend", "")).strip().lower()
        redis_url = str(
            self.env.get("ORACLE_REDIS_URL")
            or queue_cfg.get("redis_url", "")
            or ""
        ).strip()
        if backend not in {"redis", "rabbitmq"} and not redis_url:
            return RuntimeCheck("redis reachable if configured", "redis not configured", True, "config")
        if not redis_url:
            return RuntimeCheck("redis reachable if configured", "queue backend expects redis_url but none configured", False, "config")

        parsed = urllib.parse.urlparse(redis_url)
        host = parsed.hostname or ""
        if not host:
            return RuntimeCheck("redis reachable if configured", f"invalid redis url: {redis_url}", False, "config")
        port = int(parsed.port or 6379)
        timeout_s = 1.0
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                return RuntimeCheck("redis reachable if configured", f"{host}:{port}", True, "config")
        except Exception as exc:
            return RuntimeCheck("redis reachable if configured", f"{host}:{port} ({exc})", False, "config")
