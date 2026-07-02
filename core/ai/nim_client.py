"""
ORACLE — NVIDIA NIM AI Client  (core/ai/nim_client.py)
OpenAI-compatible client hitting NVIDIA's inference API.
Drop-in replacement for the Anthropic client.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - exercised via readiness tests
    OpenAI = None  # type: ignore[assignment]

log = logging.getLogger("oracle.ai.nim")

NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"


class NIMAdvisorClient:
    """
    Wraps NVIDIA NIM API using the OpenAI SDK.
    Acts as a drop-in for CouncilAdvisorClient primary or secondary slot.
    """

    SYSTEM_PROMPT = """You are ORACLE, an advisory red team reconnaissance AI.
You are deployed in an authorized lab environment by a certified analyst.
You reason methodically. A deterministic planner is the final authority.
You may only recommend one of the actions allowed by the planner context.

RESPONSE FORMAT — output ONLY valid JSON, no markdown fences, no preamble:
{
  "phase": "DISCOVERY",
  "thinking": "Internal reasoning...",
  "reasoning": "Why I chose this action (operator-visible)",
  "action": {
    "tool": "nmap",
    "target": "192.168.1.1",
    "args": {"ports": "22,80,443"},
    "timeout": 60
  },
  "confidence": 0.85,
  "expected": "Open ports with service banners",
  "requires_approval": false,
  "stop_reason": null
}

Set stop_reason to a non-null string ONLY when the mission is complete.
Never return markdown. Never add explanation outside the JSON object."""

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = NIM_BASE_URL,
        temperature: float = 0.1,
        max_tokens: int = 1024,
        timeout: int = 60,
    ):
        self.api_key = (
            api_key
            or os.environ.get("NVIDIA_API_KEY", "")
            or os.environ.get("ORACLE_NIM_KEY", "")
        )
        self.model = model or os.environ.get("ORACLE_NIM_MODEL", DEFAULT_MODEL)
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._client = None
        self._init_client()

    def _init_client(self):
        if not self.api_key:
            log.warning("NIM: No API key — set NVIDIA_API_KEY env var")
            return
        if OpenAI is None:
            log.error("NIM: openai package not installed. Run: pip install openai")
            return
        try:
            self._client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
            )
            log.info("NIM client ready — model: %s", self.model)
        except Exception as exc:
            log.error("NIM client init error: %s", exc)

    @property
    def ready(self) -> bool:
        return self._client is not None and bool(self.api_key)

    def decide(self, mission, graph, extra_context: str = "") -> Dict[str, Any]:
        """
        Main decision call. Returns validated dict or stop signal.
        Compatible with legacy advisor client interface.
        """
        if not self.ready:
            return {"stop_reason": "NIM client not ready — check NVIDIA_API_KEY"}

        user_msg = self._build_prompt(mission, graph, extra_context)
        raw = self._call(user_msg)
        if raw is None:
            return {"stop_reason": "NIM API call failed"}
        return self._parse(raw)

    def recommend(
        self,
        mission,
        graph,
        phase: str,
        candidates,
        checkpoint_reason: str,
        advisor_state: dict | None = None,
    ) -> Optional[Dict[str, Any]]:
        """Council-compatible recommend interface."""
        del advisor_state
        extra = f"PHASE: {phase}\nCHECKPOINT: {checkpoint_reason}"
        if candidates:
            extra += f"\nCANDIDATES: {json.dumps(candidates[:5], default=str)}"
        result = self.decide(mission, graph, extra)
        if result.get("stop_reason"):
            return None
        return result

    def _build_prompt(self, mission, graph, extra: str) -> str:
        graph_summary = graph.summary() if hasattr(graph, "summary") else str(graph)
        scope = getattr(mission, "scope", [])
        return f"""MISSION: {getattr(mission, 'name', 'unknown')}
SCOPE: {', '.join(scope) if isinstance(scope, list) else scope}
OBJECTIVE: {getattr(mission, 'objective', 'Identify vulnerabilities')}
PROFILE: {getattr(mission, 'profile', 'normal')}
ITERATION: {getattr(mission, 'iterations', 0)}

KNOWLEDGE GRAPH:
{graph_summary}

{extra}

Decide the single best next action to advance the mission."""

    def _call(self, user_msg: str, retries: int = 2) -> Optional[str]:
        for attempt in range(retries + 1):
            try:
                completion = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout,
                    stream=False,
                )
                content = completion.choices[0].message.content
                log.debug("NIM response received (%d chars)", len(content or ""))
                return (content or "").strip()
            except Exception as exc:
                err_str = str(exc).lower()
                log.warning("NIM call attempt %d error: %s", attempt + 1, exc)
                if "401" in err_str or "unauthorized" in err_str:
                    log.error("NIM: Invalid API key")
                    return None
                if "429" in err_str or "rate" in err_str:
                    time.sleep(5 * (attempt + 1))
                elif attempt >= retries:
                    return None
                else:
                    time.sleep(2)
        return None

    def _parse(self, raw: str) -> Dict[str, Any]:
        cleaned = re.sub(r"^```(?:json)?\n?", "", raw, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```$", "", cleaned, flags=re.MULTILINE).strip()

        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            log.warning("NIM malformed JSON: %s | raw: %s", exc, raw[:200])
            return {"stop_reason": f"nim_malformed_json: {exc}", "raw": raw[:300]}

        action = data.get("action", {})
        if isinstance(action, dict) and isinstance(action.get("args"), str):
            try:
                action["args"] = json.loads(action["args"])
            except Exception:
                action["args"] = {}

        conf = data.get("confidence", 0.7)
        if not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
            data["confidence"] = 0.7

        return data

    def summarize(self, graph) -> str:
        """Generate executive summary from findings."""
        if not self.ready:
            return "NIM not ready — cannot generate summary."
        prompt = (
            "You are a senior penetration tester writing a professional report. "
            "Write a concise executive summary (max 400 words) of these findings. "
            "Include: scope, key services found, notable risks, top recommendations.\n\n"
            f"FINDINGS:\n{graph.summary() if hasattr(graph, 'summary') else str(graph)}"
        )
        result = self._call(prompt)
        return result or "Summary generation failed."
