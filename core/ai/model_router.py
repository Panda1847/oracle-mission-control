"""Routes advisory calls to configured AI backends with deterministic fallback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import yaml

from .council import CouncilAdvisorClient
from .local_fallback import LocalFallbackAdvisor
from .nim_client import NIMAdvisorClient
from .ollama_client import OllamaAdvisorClient


class ModelRouter:
    """Provides primary/fallback routing for advisory AI calls."""

    VALID_BACKENDS = {"auto", "anthropic", "ollama", "council", "deterministic", "nim"}

    def __init__(
        self,
        client=None,
        *,
        config: dict[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        ollama_client=None,
    ):
        self.client = client
        self.local = LocalFallbackAdvisor()
        self.env = dict(env or os.environ)
        self.config = config if isinstance(config, dict) else self._load_config()
        self.advisor_config = self.config.get("advisor", {}) if isinstance(self.config.get("advisor"), dict) else {}
        self.ollama_config = self.config.get("ollama", {}) if isinstance(self.config.get("ollama"), dict) else {}
        self.backend = self._resolve_backend()
        self.ollama = ollama_client if ollama_client is not None else self._build_ollama_client()
        self.nim = self._build_nim_client()
        self.council = CouncilAdvisorClient(
            primary_client=self.nim if self._is_ready(self.nim) else self.client,
            secondary_client=self.ollama,
        )
        self._active = self._select_active()

    def _load_config(self) -> dict[str, Any]:
        root = Path(__file__).resolve().parents[2]
        config_path = root / "config" / "ai.yaml"
        if not config_path.exists():
            return {}
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}

    def _resolve_backend(self) -> str:
        raw = (
            self.env.get("ORACLE_AI_BACKEND")
            or self.env.get("ORACLE_ADVISOR_BACKEND")
            or self.advisor_config.get("backend")
            or "auto"
        )
        backend = str(raw).strip().lower()
        return backend if backend in self.VALID_BACKENDS else "auto"

    def _build_ollama_client(self):
        timeout_raw = self.ollama_config.get("timeout", 60)
        try:
            timeout_s = int(timeout_raw)
        except Exception:
            timeout_s = 60
        temperature = self.ollama_config.get("temperature", 0.1)
        try:
            temp_value = float(temperature)
        except Exception:
            temp_value = 0.1

        return OllamaAdvisorClient(
            host=str(self.ollama_config.get("host", "http://127.0.0.1:11434")),
            model=str(self.ollama_config.get("model", "llama3.2:3b")),
            timeout_s=max(5, timeout_s),
            temperature=temp_value,
            keep_alive=str(self.ollama_config.get("keep_alive", "5m")),
            enabled=bool(self.ollama_config.get("enabled", True)),
        )

    def _build_nim_client(self) -> NIMAdvisorClient:
        nim_cfg = self.config.get("nim", {}) if isinstance(self.config.get("nim"), dict) else {}
        return NIMAdvisorClient(
            api_key=self.env.get("NVIDIA_API_KEY") or self.env.get("ORACLE_NIM_KEY") or nim_cfg.get("api_key", ""),
            model=self.env.get("ORACLE_NIM_MODEL") or nim_cfg.get("model", "meta/llama-3.1-70b-instruct"),
            temperature=float(nim_cfg.get("temperature", 0.1)),
            max_tokens=int(nim_cfg.get("max_tokens", 1024)),
            timeout=int(nim_cfg.get("timeout", 60)),
        )

    @staticmethod
    def _is_ready(candidate) -> bool:
        if candidate is None:
            return False
        try:
            value = getattr(candidate, "ready")
        except AttributeError:
            # Legacy advisor clients may not expose a readiness property.
            return True
        except Exception:
            return False
        return bool(value)

    def _select_active(self):
        if self.backend == "deterministic":
            return self.local
        if self.backend == "nim":
            if self._is_ready(self.nim):
                return self.nim
            if self._is_ready(self.client):
                return self.client
            return self.local
        if self.backend == "anthropic":
            return self.client if self._is_ready(self.client) else self.local
        if self.backend == "ollama":
            return self.ollama if self._is_ready(self.ollama) else self.local
        if self.backend == "council":
            return self.council if self._is_ready(self.council) else self.local
        if self._is_ready(self.nim):
            return self.nim
        if self._is_ready(self.client):
            return self.client
        if self._is_ready(self.ollama):
            return self.ollama
        return self.local

    def active(self):
        return self._active

    def fallback(self):
        return self.local
