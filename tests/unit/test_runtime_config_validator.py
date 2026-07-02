from pathlib import Path

from oracle.runtime.config_validator import RuntimeConfigValidator
from oracle.plugins.base import ToolPlugin


class _StubPlugin(ToolPlugin):
    name = "stub"
    description = "stub"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "echo ok"

    def parse(self, stdout, stderr):
        return {"status": "ok", "data": {}, "error": ""}


class _StubRegistry:
    def __init__(self):
        self._plugin = _StubPlugin()

    def available_map(self):
        return {"stub": True}

    def get(self, name):
        return self._plugin if name == "stub" else None


def _check_map(results):
    return {item.name: item for item in results}


def test_runtime_config_validator_detects_bad_worker_secret(tmp_path):
    validator = RuntimeConfigValidator(
        registry=_StubRegistry(),
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        config={"workers": {"shared_secret": "short"}},
    )
    checks = _check_map(validator.run())
    assert checks["worker secret sane"].ok is False


def test_runtime_config_validator_marks_redis_unreachable(tmp_path):
    validator = RuntimeConfigValidator(
        registry=_StubRegistry(),
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        config={
            "workers": {"shared_secret": "very-strong-worker-secret-123"},
            "queue": {"backend": "redis", "redis_url": "redis://127.0.0.1:1/0"},
        },
    )
    checks = _check_map(validator.run())
    assert checks["redis reachable if configured"].ok is False


def test_runtime_config_validator_reads_legacy_toml_sections(tmp_path):
    validator = RuntimeConfigValidator(
        registry=_StubRegistry(),
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        config={
            "legacy": {
                "workers": {"shared_secret": "short"},
                "queue": {"backend": "redis", "redis_url": "redis://127.0.0.1:1/0"},
            }
        },
    )
    checks = _check_map(validator.run())
    assert checks["worker secret sane"].ok is False
    assert checks["redis reachable if configured"].ok is False
