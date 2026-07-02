"""
ORACLE — pytest configuration  (conftest.py)
Shared fixtures available to all test modules.
"""
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure oracle package is importable from project root
sys.path.insert(0, str(Path(__file__).parent))


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir():
    """Temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def storage(tmp_dir):
    from oracle.memory.storage import Storage
    return Storage(tmp_dir)


@pytest.fixture
def graph(storage):
    from oracle.memory.graph import KnowledgeGraph
    return KnowledgeGraph("test_mission", storage)


@pytest.fixture
def safety():
    from oracle.runtime.safety import SafetyValidator
    return SafetyValidator(scope=["192.168.56.0/24", "127.0.0.1"])


@pytest.fixture
def registry():
    from oracle.plugins.base import PluginRegistry
    from oracle.plugins.nmap import NmapPlugin
    from oracle.plugins.http import HttpPlugin
    from oracle.plugins.fuzz import FuzzPlugin
    reg = PluginRegistry()
    reg._plugins["nmap"] = NmapPlugin()
    reg._plugins["http"] = HttpPlugin()
    reg._plugins["fuzz"] = FuzzPlugin()
    return reg


@pytest.fixture
def executor(registry):
    from oracle.runtime.executor import Executor
    return Executor(registry)


@pytest.fixture
def mission():
    from oracle.core.models import Mission
    return Mission(
        name="test_mission",
        scope=["192.168.56.0/24"],
        objective="Test mission",
        profile="normal",
    )
