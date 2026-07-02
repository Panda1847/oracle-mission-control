from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml


def default_config_path() -> Path:
    return Path.home() / ".oracle" / "config.toml"


DEFAULT_ENV = "development"


def _load_toml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if not path.exists():
        return data
    raw = path.read_bytes()
    try:
        import tomllib  # py>=3.11
        loaded = tomllib.loads(raw.decode("utf-8"))
    except Exception:
        try:
            import tomli  # type: ignore

            loaded = tomli.loads(raw.decode("utf-8"))
        except Exception:
            return {}
    return loaded if isinstance(loaded, dict) else {}


def load_config(path: Optional[Path] = None) -> dict[str, Any]:
    """
    Loads config.toml. Expected format:

    [oracle]
    scope=["127.0.0.1"]
    profile="normal"
    web=true
    web_port=5000
    online_cve=false
    """
    manager = ConfigManager()
    merged = manager.load()
    p = path or default_config_path()
    data = _load_toml(p)

    # Merge known legacy TOML tables into top-level keys for CLI defaults.
    legacy: dict[str, Any] = dict(data) if isinstance(data, dict) else {}
    for table in ("oracle", "opsec", "alerts", "web"):
        t = data.get(table) if isinstance(data, dict) else None
        if isinstance(t, dict):
            legacy.update(t)
            legacy.pop(table, None)

    return _deep_merge(merged, {"legacy": legacy})


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


class ConfigManager:
    """Validated YAML config loader with environment overlays and hot reload."""

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        *,
        environment: Optional[str] = None,
        mission_overrides: Optional[dict[str, Any]] = None,
    ):
        self.root_dir = Path(root_dir or Path(__file__).resolve().parents[2])
        self.config_dir = self.root_dir / "config"
        self.environment = environment or DEFAULT_ENV
        self.mission_overrides = mission_overrides or {}
        self._mtimes: dict[Path, float] = {}
        self._loaded: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        merged = {}
        files = [
            self.config_dir / "default.yaml",
            self.config_dir / f"{self.environment}.yaml",
            self.config_dir / "workers.yaml",
            self.config_dir / "plugins.yaml",
            self.config_dir / "ai.yaml",
            self.config_dir / "policy.yaml",
        ]
        for path in files:
            if not path.exists():
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError(f"invalid config file: {path}")
            merged = _deep_merge(merged, data)
            self._mtimes[path] = path.stat().st_mtime
        if self.mission_overrides:
            merged = _deep_merge(merged, {"mission_overrides": dict(self.mission_overrides)})
        self._validate(merged)
        self._loaded = merged
        return merged

    def reload_if_changed(self) -> dict[str, Any]:
        if not self._loaded:
            return self.load()
        for path, old_mtime in list(self._mtimes.items()):
            if path.exists() and path.stat().st_mtime != old_mtime:
                return self.load()
        return dict(self._loaded)

    def _validate(self, data: dict[str, Any]):
        mission = data.get("mission", {})
        runtime = data.get("runtime", {})
        workers = data.get("workers", {})
        advisor = data.get("advisor", {})
        if not isinstance(mission, dict):
            raise ValueError("mission config must be a mapping")
        if int(mission.get("max_iterations", 1) or 1) <= 0:
            raise ValueError("mission.max_iterations must be positive")
        if not isinstance(runtime, dict):
            raise ValueError("runtime config must be a mapping")
        if int(runtime.get("default_timeout", 1) or 1) <= 0:
            raise ValueError("runtime.default_timeout must be positive")
        mode = str(runtime.get("mode", "live")).lower().strip()
        if mode not in {"live", "lab", "test"}:
            raise ValueError("runtime.mode must be one of: live, lab, test")
        if not isinstance(workers, dict):
            raise ValueError("workers config must be a mapping")
        if not isinstance(advisor, dict):
            raise ValueError("advisor config must be a mapping")


def argparse_defaults_from_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns a mapping suitable for `argparse.ArgumentParser.set_defaults(**...)`.
    Only whitelisted keys are accepted.
    """
    allowed = {
        "scope",
        "mission_name",
        "objective",
        "profile",
        "max_iter",
        "api_key",
        "demo",
        "demo_speed",
        "copilot",
        "report",
        "web",
        "web_port",
        "online_cve",
        "nvd_api_key",
        "vulners_api_key",
        # opsec/alerts
        "action_jitter",
        "network_throttle",
        "webhook_url",
        "webhook_timeout",
        "webhook_queue_max",
        "web_auth_token",
        "web_auth_user",
        "web_auth_pass",
    }
    out: Dict[str, Any] = {}
    # Flatten modern YAML sections and keep legacy TOML compatibility.
    merged = dict((cfg or {}).get("legacy", {}))
    for section in ("mission", "runtime", "advisor", "logging"):
        section_data = (cfg or {}).get(section, {})
        if isinstance(section_data, dict):
            merged.update(section_data)
    for k, v in merged.items():
        if k in allowed:
            out[k] = v
    # normalize scope
    if "scope" in out and isinstance(out["scope"], str):
        out["scope"] = [out["scope"]]
    return out
