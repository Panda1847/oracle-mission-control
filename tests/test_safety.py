"""
ORACLE — Tests  (tests/test_safety.py)
"""
import pytest, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.models import Action
from oracle.runtime.safety import SafetyValidator


@pytest.fixture
def safety():
    return SafetyValidator(scope=["192.168.56.0/24", "127.0.0.1"])


def make_action(tool="nmap", target="192.168.56.1"):
    return Action(tool=tool, target=target, args={})


# ── Tool whitelist ────────────────────────────────────────────────────────────

def test_allowed_tool_nmap(safety):
    ok, _ = safety.validate(make_action("nmap", "192.168.56.1"), "nmap -sV 192.168.56.1")
    assert ok

def test_allowed_tool_http(safety):
    ok, _ = safety.validate(make_action("http", "192.168.56.1"), "curl http://192.168.56.1")
    assert ok

def test_allowed_tool_fuzz(safety):
    ok, _ = safety.validate(make_action("fuzz", "192.168.56.1"), "gobuster dir ...")
    assert ok

def test_blocked_tool(safety):
    ok, reason = safety.validate(make_action("hydra", "192.168.56.1"), "hydra ...")
    assert not ok
    assert "whitelist" in reason.lower()


# ── Scope enforcement ─────────────────────────────────────────────────────────

def test_in_scope_ip(safety):
    assert safety.in_scope("192.168.56.50")

def test_out_of_scope_ip(safety):
    ok, reason = safety.validate(make_action(target="10.0.0.1"), "nmap 10.0.0.1")
    assert not ok
    assert "SCOPE" in reason

def test_loopback_always_in_scope(safety):
    assert safety.in_scope("127.0.0.1")
    assert safety.in_scope("localhost")


# ── Blocklist ─────────────────────────────────────────────────────────────────

def test_blocks_rm_rf(safety):
    ok, reason = safety.validate(make_action(target="192.168.56.1"), "rm -rf / --no-preserve-root")
    assert not ok
    assert "rm -rf" in reason

def test_blocks_shutdown(safety):
    ok, reason = safety.validate(make_action(target="192.168.56.1"), "shutdown -h now")
    assert not ok

def test_blocks_fork_bomb(safety):
    ok, reason = safety.validate(make_action(target="192.168.56.1"), ":(){:|:&};:")
    assert not ok

def test_blocks_mkfs(safety):
    ok, reason = safety.validate(make_action(target="192.168.56.1"), "mkfs.ext4 /dev/sda")
    assert not ok


# ── Scope summary ─────────────────────────────────────────────────────────────

def test_scope_summary(safety):
    s = safety.scope_summary()
    assert "192.168.56.0/24" in s

def test_empty_scope_allows_all():
    s = SafetyValidator(scope=[])
    ok, _ = s.validate(make_action(target="10.10.10.10"), "nmap 10.10.10.10")
    assert ok
