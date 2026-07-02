import time
from pathlib import Path

from oracle.core.config import ConfigManager


def test_config_manager_loads_environment_and_hot_reloads(tmp_path):
    root = tmp_path
    config_dir = root / "config"
    config_dir.mkdir()
    (config_dir / "default.yaml").write_text("mission:\n  max_iterations: 10\nruntime:\n  default_timeout: 30\n")
    (config_dir / "development.yaml").write_text("logging:\n  level: DEBUG\n")
    (config_dir / "workers.yaml").write_text("workers:\n  mode: local\n")
    (config_dir / "plugins.yaml").write_text("plugins:\n  enabled: [nmap]\n")
    (config_dir / "ai.yaml").write_text("advisor:\n  enabled: true\n")
    (config_dir / "policy.yaml").write_text("phases: {}\n")

    manager = ConfigManager(root, environment="development")
    loaded = manager.load()
    assert loaded["mission"]["max_iterations"] == 10
    assert loaded["logging"]["level"] == "DEBUG"

    time.sleep(0.01)
    (config_dir / "development.yaml").write_text("logging:\n  level: INFO\n")
    reloaded = manager.reload_if_changed()
    assert reloaded["logging"]["level"] == "INFO"

