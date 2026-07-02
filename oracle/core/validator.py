"""
ORACLE — Schema Validator  (core/validator.py)
Validates AI decision dicts before execution.
"""
from __future__ import annotations
from typing import Dict, Tuple, Any

VALID_TOOLS  = {"nmap", "http", "fuzz"}
VALID_PHASES = {"recon", "enum", "exploit", "post", "report"}


class SchemaValidator:
    """
    Two-pass validator:
    1. Structure check  — required keys exist and have correct types
    2. Content check    — values are within allowed enumerations
    """

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        if not isinstance(data, dict):
            return False, "Response is not a JSON object"

        # stop_reason short-circuit
        if data.get("stop_reason"):
            return True, "Stop signal"

        # Top-level required
        for key in ("phase", "reasoning", "action"):
            if key not in data:
                return False, f"Missing top-level key: '{key}'"

        # Phase valid
        if data["phase"] not in VALID_PHASES:
            return False, f"Invalid phase: '{data['phase']}'"

        # Action structure
        action = data["action"]
        if not isinstance(action, dict):
            return False, "'action' must be an object"

        for key in ("tool", "target", "args"):
            if key not in action:
                return False, f"Action missing key: '{key}'"

        # Tool allowed
        if action["tool"] not in VALID_TOOLS:
            return False, f"Tool not in whitelist: '{action['tool']}'. Allowed: {VALID_TOOLS}"

        # Args must be a dict
        if not isinstance(action.get("args"), dict):
            return False, "'args' must be a JSON object"

        # Confidence range
        conf = data.get("confidence", 0.7)
        if not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
            data["confidence"] = 0.7   # fix silently

        return True, "OK"

    def fix(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort repair of minor issues."""
        if "action" in data and isinstance(data["action"], dict):
            act = data["action"]
            # Convert string args to dict
            if isinstance(act.get("args"), str):
                import json
                try:
                    act["args"] = json.loads(act["args"])
                except Exception:
                    act["args"] = {}
            if act.get("args") is None:
                act["args"] = {}
            # Default timeout
            if "timeout" not in act:
                act["timeout"] = 60
        return data
