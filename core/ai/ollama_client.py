"""Local Ollama advisory client for deterministic ORACLE missions."""

from __future__ import annotations

import json
import re
import textwrap
import time
import urllib.error
import urllib.request
from typing import Any, Dict


class OllamaAdvisorClient:
    """Minimal Ollama client that exposes the same `decide(...)` contract."""

    def __init__(
        self,
        *,
        host: str = "http://127.0.0.1:11434",
        model: str = "llama3.2:3b",
        timeout_s: int = 60,
        temperature: float = 0.1,
        keep_alive: str = "5m",
        enabled: bool = True,
    ):
        self.host = str(host).strip().rstrip("/")
        self.model = str(model).strip()
        self.timeout_s = int(timeout_s)
        self.temperature = float(temperature)
        self.keep_alive = str(keep_alive).strip()
        self.enabled = bool(enabled)
        self._ready_cache: bool | None = None
        self._ready_checked_at = 0.0

    @property
    def ready(self) -> bool:
        return self._is_ready(refresh=False)

    def _url(self, path: str) -> str:
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{self.host}{suffix}"

    def _request_json(
        self,
        url: str,
        payload: Dict[str, Any] | None = None,
        *,
        timeout: int | float | None = None,
    ) -> Dict[str, Any] | None:
        data = None
        headers = {}
        method = "GET"
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout or self.timeout_s) as resp:
                body = resp.read().decode("utf-8")
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None
        except Exception:
            return None

    def _is_ready(self, *, refresh: bool = False) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        if not refresh and self._ready_cache is not None and (now - self._ready_checked_at) < 10:
            return self._ready_cache
        tags = self._request_json(self._url("/api/tags"), timeout=min(max(self.timeout_s, 1), 3))
        ready = False
        if isinstance(tags, dict):
            models = tags.get("models", [])
            names = set()
            if isinstance(models, list):
                for item in models:
                    if not isinstance(item, dict):
                        continue
                    for key in ("name", "model"):
                        value = str(item.get(key, "")).strip()
                        if value:
                            names.add(value)
            if self.model in names:
                ready = True
            else:
                base = self.model.split(":", 1)[0]
                ready = any(name.split(":", 1)[0] == base for name in names)
        self._ready_cache = ready
        self._ready_checked_at = now
        return ready

    def _build_prompt(self, mission, graph, extra: str) -> str:
        scope = ", ".join(getattr(mission, "scope", []) or [])
        return textwrap.dedent(
            f"""
            MISSION: {getattr(mission, "name", "oracle_mission")}
            SCOPE: {scope}
            OBJECTIVE: {getattr(mission, "objective", "")}
            PROFILE: {getattr(mission, "profile", "")}
            ITERATION: {getattr(mission, "iterations", 0)}/{getattr(mission, "max_iterations", 0)}

            KNOWLEDGE GRAPH:
            {graph.summary() if hasattr(graph, "summary") else ""}

            {extra}

            Return only valid JSON with:
            {{
              "reasoning": "string",
              "action": {{"tool": "nmap|http|fuzz", "target": "host-or-url", "args": {{}}}},
              "confidence": 0.0,
              "expected": "string"
            }}
            """
        ).strip()

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned.strip())
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            return {"stop_reason": f"malformed_json:{exc}"}
        if not isinstance(parsed, dict):
            return {"stop_reason": "invalid_response_object"}
        # Allow models to return either {"action": ...} or top-level tool/target.
        if "action" not in parsed and parsed.get("tool") and parsed.get("target"):
            parsed["action"] = {
                "tool": parsed.get("tool"),
                "target": parsed.get("target"),
                "args": parsed.get("args", {}),
            }
        return parsed

    def decide(self, mission, graph, extra: str = "") -> Dict[str, Any]:
        if not self._is_ready(refresh=False):
            return {
                "stop_reason": (
                    f"Ollama not ready for model '{self.model}'. "
                    f"Run: ollama pull {self.model}"
                )
            }

        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": self._build_prompt(mission, graph, extra),
            "stream": False,
            "keep_alive": self.keep_alive or "5m",
            "options": {"temperature": self.temperature},
        }
        response = self._request_json(self._url("/api/generate"), payload, timeout=self.timeout_s)
        if not isinstance(response, dict):
            return {"stop_reason": "ollama_request_failed"}
        raw = str(response.get("response", "") or "").strip()
        if not raw:
            return {"stop_reason": "ollama_empty_response"}
        return self._parse_response(raw)
