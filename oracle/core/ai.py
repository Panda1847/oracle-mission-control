"""
ORACLE — AI Decision Engine  (core/ai.py)
Schema-enforced Claude API interface.
Malformed responses NEVER crash the mission loop.
"""
from __future__ import annotations
import json
import logging
import os
import re
import time
import textwrap
import urllib.error
import urllib.request
from typing import Dict, Any, Optional

from .models import Mission
from ..memory.graph import KnowledgeGraph

log = logging.getLogger("oracle.ai")

# ── Schema ────────────────────────────────────────────────────────────────────

REQUIRED     = ("phase", "reasoning", "action")
ACT_REQUIRED = ("tool", "target", "args")
VALID_PHASES = (
    "recon",
    "enum",
    "exploit",
    "post",
    "report",
    "INIT",
    "DISCOVERY",
    "ENUMERATION",
    "VALIDATION",
    "EXPLOIT_ANALYSIS",
    "POST_PROCESS",
    "REPORTING",
    "COMPLETE",
    "FAILED",
    "PAUSED",
)

TOOLS_DOC = textwrap.dedent("""
AVAILABLE TOOLS (use the exact name string):
  nmap   — TCP port scan + service/version detection
  http   — Single HTTP request (headers, status, body)
  fuzz   — Web directory/path fuzzing (gobuster / ffuf)

ARGS must be a JSON object.  Examples:
  nmap:  {"ports": "22,80,443,8080", "timing": "T3"}
  http:  {"port": 80, "path": "/", "method": "GET"}
  fuzz:  {"port": 80, "wordlist": "common", "extensions": "php,txt"}
""").strip()

SYSTEM_PROMPT = textwrap.dedent(f"""
You are ORACLE, an advisory red team reconnaissance AI.
You are deployed in an authorized lab environment by a certified analyst.
You reason methodically, but a deterministic planner is the final authority.
You may only recommend one of the actions allowed by the planner context.

{TOOLS_DOC}

OPERATOR DIRECTIVES take absolute priority over your own plan.
You may explain uncertainty, but you do not decide phase transitions, retries, or mission completion.

RESPONSE FORMAT — output ONLY valid JSON, no markdown fences:
{{
  "phase":            "DISCOVERY",
  "thinking":         "Internal step-by-step reasoning (not shown to operator by default)",
  "reasoning":        "Why this allowed action is the best recommendation",
  "action": {{
    "tool":           "nmap",
    "target":         "192.168.56.1",
    "args":           {{"ports": "22,80,443"}},
    "timeout":        60
  }},
  "confidence":       0.85,
  "expected":         "Open ports with service banners",
  "requires_approval": false,
  "stop_reason":      null
}}

Set stop_reason to null unless the planner explicitly asks for a stop recommendation.
requires_approval must be true whenever you are unsure of impact.
""").strip()


# ── Validator ─────────────────────────────────────────────────────────────────

def validate(data: Dict) -> tuple[bool, str]:
    for f in REQUIRED:
        if f not in data:
            return False, f"Missing field: '{f}'"
    act = data.get("action", {})
    if not isinstance(act, dict):
        return False, "'action' must be an object"
    for f in ACT_REQUIRED:
        if f not in act:
            return False, f"Action missing: '{f}'"
    if act.get("args") is None:
        act["args"] = {}
    if isinstance(act.get("args"), str):
        try:
            act["args"] = json.loads(act["args"])
        except Exception:
            act["args"] = {}
    if data.get("phase") not in VALID_PHASES:
        data["phase"] = "recon"
    conf = data.get("confidence", 0.7)
    if not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
        data["confidence"] = 0.7
    return True, "OK"


# ── AI class ──────────────────────────────────────────────────────────────────

class OracleAI:

    MODEL       = "claude-sonnet-4-20250514"
    API_URL     = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str = ""):
        self.api_key = (
            api_key
            or os.environ.get("ORACLE_API_KEY", "")
            or os.environ.get("ANTHROPIC_API_KEY", "")
        )
        self.call_count = 0

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    # ── Public interface ──────────────────────────────────────────────────────

    def decide(self, mission: Mission, graph: KnowledgeGraph,
               extra: str = "") -> Dict[str, Any]:
        """
        Ask the LLM for a recommendation only.
        Returns a validated recommendation dict.
        On any failure returns {"stop_reason": "<reason>"}.
        """
        if not self.ready:
            return {"stop_reason": "No API key. Set ORACLE_API_KEY env var."}

        prompt = self._build_prompt(mission, graph, extra)
        raw = self._call(prompt)
        if raw is None:
            return {"stop_reason": "LLM API call failed"}
        return self._parse(raw)

    def summarize(self, graph: KnowledgeGraph) -> str:
        """Generate a short executive summary of findings."""
        if not self.ready:
            return "No API key — cannot generate summary."
        prompt = (
            "You are a senior penetration tester. Write a concise executive "
            "summary (max 400 words) of the following recon findings. "
            "Include: scope, key services found, notable risks.\n\n"
            f"FINDINGS:\n{graph.summary()}"
        )
        return self._call(prompt) or "Summary generation failed."

    def tactical_narrative(self, graph: KnowledgeGraph) -> str:
        """
        Generate an operator-facing tactical narrative of the attack path.
        This is best-effort and never required for report generation.
        """
        if not self.ready:
            return ""
        prompt = (
            "You are a senior red team operator writing a tactical mission narrative. "
            "Write a crisp, chronological story of what ORACLE discovered and how an "
            "attack path could proceed. Use concrete host:port details. If CVEs are "
            "present, mention them briefly with exploitability context. Keep it under 500 words.\n\n"
            f"GRAPH:\n{graph.summary()}"
        )
        return self._call(prompt) or ""

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_prompt(self, mission: Mission, graph: KnowledgeGraph,
                      extra: str) -> str:
        return textwrap.dedent(f"""
        MISSION: {mission.name}
        SCOPE:   {', '.join(mission.scope)}
        OBJECTIVE: {mission.objective}
        PROFILE: {mission.profile}
        ITERATION: {mission.iterations}/{mission.max_iterations}

        KNOWLEDGE GRAPH:
        {graph.summary()}

        {extra}

        Recommend the single best next action from the planner's allowed action set.
        """).strip()

    def _call(self, user_msg: str, retries: int = 2) -> Optional[str]:
        payload = json.dumps({
            "model": self.MODEL,
            "max_tokens": 1024,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }).encode()

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    self.API_URL, data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                        "anthropic-version": self.API_VERSION,
                    },
                    method="POST",
                )
                self.call_count += 1
                with urllib.request.urlopen(req, timeout=60) as r:
                    body = json.loads(r.read().decode())
                    return body["content"][0]["text"].strip()

            except urllib.error.HTTPError as e:
                msg = e.read().decode()
                log.error("HTTP %s: %s", e.code, msg[:200])
                if e.code in (429, 529):
                    time.sleep(4 * (attempt + 1))
                elif e.code in (401, 403):
                    log.error("Auth error — check ORACLE_API_KEY")
                    return None
                elif attempt >= retries:
                    return None

            except Exception as e:
                log.error("LLM error: %s", e)
                if attempt >= retries:
                    return None
                time.sleep(2)

        return None

    def _parse(self, raw: str) -> Dict[str, Any]:
        # Strip markdown fences
        cleaned = re.sub(r"^```(?:json)?\n?", "", raw, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```$", "", cleaned, flags=re.MULTILINE).strip()

        # Extract JSON object
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(0)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            log.warning("Malformed JSON from AI: %s | raw: %s", e, raw[:200])
            return {"stop_reason": f"malformed_json: {e}", "raw": raw[:300]}

        ok, reason = validate(data)
        if not ok:
            log.warning("Schema fail: %s", reason)
            return {"stop_reason": f"schema_error: {reason}", "raw": raw[:300]}

        return data
