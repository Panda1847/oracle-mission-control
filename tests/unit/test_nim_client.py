"""Tests for NVIDIA NIM client integration."""

import json
from unittest.mock import MagicMock, patch

from core.ai.nim_client import NIMAdvisorClient


def _good_response():
    return json.dumps(
        {
            "phase": "DISCOVERY",
            "thinking": "Port scanning first",
            "reasoning": "Need to discover open services",
            "action": {
                "tool": "nmap",
                "target": "192.168.1.1",
                "args": {"ports": "22,80,443"},
                "timeout": 60,
            },
            "confidence": 0.85,
            "expected": "Open ports",
            "requires_approval": False,
            "stop_reason": None,
        }
    )


def test_nim_parse_valid():
    client = NIMAdvisorClient()
    result = client._parse(_good_response())
    assert result.get("phase") == "DISCOVERY"
    assert result["action"]["tool"] == "nmap"


def test_nim_parse_strips_markdown():
    client = NIMAdvisorClient()
    wrapped = f"```json\n{_good_response()}\n```"
    result = client._parse(wrapped)
    assert result.get("phase") == "DISCOVERY"


def test_nim_parse_malformed():
    client = NIMAdvisorClient()
    result = client._parse("this is not json {{{{")
    assert "stop_reason" in result
    assert result["stop_reason"] is not None


def test_nim_ready_without_key():
    client = NIMAdvisorClient(api_key="")
    assert client.ready is False


def test_nim_ready_with_key():
    with patch("core.ai.nim_client.OpenAI"):
        client = NIMAdvisorClient(api_key="nvapi-test")
        assert client.ready is True


def test_nim_decide_no_key():
    client = NIMAdvisorClient(api_key="")
    result = client.decide(MagicMock(), MagicMock())
    assert "stop_reason" in result


def test_nim_confidence_clamped():
    client = NIMAdvisorClient()
    data = json.loads(_good_response())
    data["confidence"] = 99.0
    result = client._parse(json.dumps(data))
    assert result["confidence"] == 0.7


def test_nim_string_args_normalized():
    client = NIMAdvisorClient()
    data = json.loads(_good_response())
    data["action"]["args"] = '{"ports": "80"}'
    result = client._parse(json.dumps(data))
    assert isinstance(result["action"]["args"], dict)
