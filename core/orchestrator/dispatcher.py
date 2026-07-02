"""Distributed worker dispatcher with local fallback."""

from __future__ import annotations

import json
import logging
import os
import time
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

import yaml

from workers.auth import WorkerAuth
from workers.local_worker import LocalWorker
from workers.registration import WorkerRegistry
from workers.result_callback import ResultCallbackServer
from telemetry.health import GLOBAL_HEALTH
from telemetry.metrics import GLOBAL_METRICS

log = logging.getLogger("oracle.dispatcher")


class Dispatcher:
    """Dispatches jobs to healthy workers and falls back to local execution."""

    def __init__(self, executor, config_path: str | Path | None = None):
        self.executor = executor
        self.config = self._load_config(config_path)
        self.shared_secret = self._require_shared_secret(self.config.get("shared_secret", ""))
        self.auth = WorkerAuth(self.shared_secret)
        self.registry = WorkerRegistry(int(self.config.get("heartbeat_timeout_seconds", 45) or 45))
        self.local_worker = LocalWorker(executor, worker_id=str(self.config.get("local_worker_id", "local-node")))
        self.metrics = GLOBAL_METRICS
        self.health = GLOBAL_HEALTH
        callback_host = self._resolve_callback_host(str(self.config.get("callback_host", "127.0.0.1")))
        self.callback_server = ResultCallbackServer(
            host=callback_host,
            port=int(self.config.get("callback_port", 0) or 0),
            shared_secret=self.shared_secret,
        )
        self.callback_server.start()
        self.registry.register(
            worker_id=self.local_worker.worker_id,
            endpoint="local://executor",
            capabilities=self.local_worker.capabilities,
            transport="local",
            role="local",
        )
        self.health.report("dispatcher", "ok", {"workers": 1})

    def dispatch(self, action, command: str):
        worker = self.registry.healthiest(action.tool) or self.registry.get(self.local_worker.worker_id)
        if worker is None or worker.transport == "local":
            result = self.local_worker.execute(action, command)
            self.registry.complete(self.local_worker.worker_id, result.success)
            self.metrics.inc("worker_dispatch_total", labels={"worker": self.local_worker.worker_id, "transport": "local"})
            self.metrics.set_gauge("worker_health_score", self.registry.get(self.local_worker.worker_id).health_score, labels={"worker": self.local_worker.worker_id})
            return result
        try:
            result = self._dispatch_remote(worker.worker_id, worker.endpoint, action, command)
            self.registry.complete(worker.worker_id, result.success)
            self.metrics.inc("worker_dispatch_total", labels={"worker": worker.worker_id, "transport": worker.transport})
            self.metrics.set_gauge("worker_health_score", self.registry.get(worker.worker_id).health_score, labels={"worker": worker.worker_id})
            return result
        except Exception as exc:
            log.warning("Remote worker %s failed, falling back to local: %s", worker.worker_id, exc)
            self.registry.complete(worker.worker_id, False)
            self.health.report("dispatcher", "degraded", {"failed_worker": worker.worker_id, "reason": str(exc)})
            result = self.local_worker.execute(action, command)
            self.registry.complete(self.local_worker.worker_id, result.success)
            self.metrics.inc("worker_dispatch_fallback_total", labels={"worker": worker.worker_id})
            return result

    def register_remote_worker(self, worker_id: str, endpoint: str, capabilities: list[str], metadata: dict | None = None):
        if self._is_remote_endpoint(endpoint) and self._is_loopback_host(self.callback_server.host):
            raise ValueError(
                "workers.callback_host is loopback and cannot be reached by remote workers. "
                "Set workers.callback_host to a routable host/IP before registering remote workers."
            )
        self.registry.register(
            worker_id=worker_id,
            endpoint=endpoint,
            capabilities=capabilities,
            transport="http",
            role="remote",
            metadata=metadata or {},
        )
        return self.registry.get(worker_id)

    def shutdown(self):
        self.callback_server.stop()
        self.health.report("dispatcher", "down", {"workers": len(self.registry.all())})

    def _dispatch_remote(self, worker_id: str, endpoint: str, action, command: str):
        job_id = uuid4().hex
        metadata = (self.registry.get(worker_id).metadata if self.registry.get(worker_id) else {}) or {}
        payload = {
            "job_id": job_id,
            "command": command,
            "timeout_seconds": int(action.timeout),
            "callback_url": self.callback_server.callback_url,
            "tool": action.tool,
            "target": action.target,
        }
        headers = {"Content-Type": "application/json", **self.auth.sign(payload)}
        req = urllib.request.Request(
            f"{endpoint.rstrip('/')}/jobs",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=max(5, action.timeout), context=self._ssl_context_for(metadata, endpoint)) as resp:
            ack = json.loads(resp.read().decode("utf-8"))
        if not ack.get("accepted"):
            raise RuntimeError(f"worker {worker_id} rejected job")
        self.registry.acknowledge(worker_id)
        callback = self.callback_server.wait_for(job_id, timeout=action.timeout + 5)
        if not callback:
            raise TimeoutError(f"worker {worker_id} did not callback for job {job_id}")
        return self.executor.build_action_result(
            action,
            command,
            callback.get("stdout", ""),
            callback.get("stderr", ""),
            int(callback.get("returncode", -1)),
            float(callback.get("duration_ms", 0)) / 1000.0,
            worker_id=worker_id,
        )

    def _load_config(self, config_path: str | Path | None):
        root = Path(__file__).resolve().parents[2]
        path = Path(config_path or (root / "config" / "workers.yaml"))
        data = yaml.safe_load(path.read_text()) or {}
        return dict(data.get("workers", data))

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        lowered = str(host or "").strip().lower()
        return lowered in {"127.0.0.1", "localhost", "::1", ""}

    @staticmethod
    def _is_remote_endpoint(endpoint: str) -> bool:
        parsed = urllib.parse.urlparse(str(endpoint))
        host = (parsed.hostname or "").strip().lower()
        return host not in {"", "127.0.0.1", "localhost", "::1"}

    @staticmethod
    def _resolve_callback_host(configured_host: str) -> str:
        host = str(configured_host or "").strip()
        if host:
            return host
        return "127.0.0.1"

    @staticmethod
    def _require_shared_secret(raw_secret: str) -> str:
        return WorkerAuth.resolve_shared_secret(
            raw_secret,
            allow_insecure=str(os.environ.get("ORACLE_ALLOW_INSECURE_WORKER_SECRET", "")).strip().lower()
            in {"1", "true", "yes", "on"},
        )

    def _ssl_context_for(self, metadata: dict, endpoint: str):
        if not str(endpoint).startswith("https://"):
            return None
        context = ssl.create_default_context(cafile=metadata.get("tls_ca_file") or None)
        certfile = metadata.get("tls_certfile") or ""
        keyfile = metadata.get("tls_keyfile") or ""
        if certfile and keyfile:
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return context

    def health_snapshot(self):
        return {
            "dispatcher": self.health.summary(),
            "workers": [
                {
                    "worker_id": record.worker_id,
                    "health_score": record.health_score,
                    "role": record.role,
                    "transport": record.transport,
                    "inflight_jobs": record.inflight_jobs,
                }
                for record in self.registry.all().values()
            ],
        }
