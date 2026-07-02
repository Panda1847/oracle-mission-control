"""ORACLE — Tests  (tests/test_ai.py)"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.ai import OracleAI, validate
from oracle.core.validator import SchemaValidator


# ── Schema validation ─────────────────────────────────────────────────────────

def _good():
    return {
        "phase": "recon",
        "thinking": "...",
        "reasoning": "Port scan first",
        "action": {
            "tool": "nmap",
            "target": "192.168.1.1",
            "args": {"ports": "80,443"},
            "timeout": 60,
        },
        "confidence": 0.9,
        "stop_reason": None,
    }

def test_valid_schema():
    ok, msg = validate(_good())
    assert ok, msg

def test_missing_phase():
    d = _good(); del d["phase"]
    ok, _ = validate(d)
    assert not ok

def test_missing_action():
    d = _good(); del d["action"]
    ok, _ = validate(d)
    assert not ok

def test_missing_tool():
    d = _good(); del d["action"]["tool"]
    ok, _ = validate(d)
    assert not ok

def test_missing_target():
    d = _good(); del d["action"]["target"]
    ok, _ = validate(d)
    assert not ok

def test_invalid_phase_corrected():
    d = _good(); d["phase"] = "unknown_phase"
    ok, _ = validate(d)
    # validate fixes phase silently
    assert d["phase"] == "recon"

def test_confidence_out_of_range():
    d = _good(); d["confidence"] = 5.0
    ok, _ = validate(d)
    assert d["confidence"] == 0.7   # fixed silently


# ── JSON parsing ──────────────────────────────────────────────────────────────

def test_parse_strips_markdown():
    ai = OracleAI()
    raw = "```json\n" + json.dumps(_good()) + "\n```"
    result = ai._parse(raw)
    assert "stop_reason" not in result or result.get("stop_reason") is None
    assert result.get("phase") == "recon"

def test_parse_malformed_json():
    ai = OracleAI()
    result = ai._parse("This is not JSON at all {{{{")
    assert "stop_reason" in result
    assert "malformed" in result["stop_reason"]

def test_parse_schema_error():
    ai = OracleAI()
    bad = {"phase": "recon", "reasoning": "ok"}   # no "action"
    result = ai._parse(json.dumps(bad))
    assert "stop_reason" in result

def test_parse_string_args_converted():
    ai = OracleAI()
    d = _good()
    d["action"]["args"] = '{"ports": "22,80"}'   # AI returns string instead of dict
    result = ai._parse(json.dumps(d))
    assert isinstance(result["action"]["args"], dict)


# ── SchemaValidator tool whitelist ────────────────────────────────────────────

def test_schema_validator_tool_not_whitelisted():
    sv = SchemaValidator()
    d = _good(); d["action"]["tool"] = "sqlmap"
    ok, reason = sv.validate(d)
    assert not ok
    assert "whitelist" in reason.lower()

def test_schema_validator_allowed_tools():
    sv = SchemaValidator()
    for tool in ("nmap", "http", "fuzz"):
        d = _good(); d["action"]["tool"] = tool
        ok, _ = sv.validate(d)
        assert ok, f"Tool {tool} should be allowed"
