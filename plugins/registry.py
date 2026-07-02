"""Manifest-driven plugin registry."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .dependency_check import health_status
from .validator import validate_manifest


@dataclass
class PluginManifest:
    name: str
    version: str
    category: str
    capabilities: List[str]
    required_binaries: List[str]
    risk_level: str
    expected_artifacts: List[str]
    parser_schema: str
    timeout: int
    retry_policy: Dict[str, Any]
    confidence_weight: float
    approval_required: bool


class EnterprisePluginRegistry:
    """Loads plugins from the new root `plugins/*` directory structure."""

    def __init__(self):
        self._plugins: Dict[str, object] = {}
        self._manifests: Dict[str, PluginManifest] = {}
        self._health: Dict[str, Dict[str, object]] = {}

    def load_from_root(self, root: Path) -> int:
        count = 0
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "manifest.yaml"
            plugin_path = entry / "plugin.py"
            if not manifest_path.exists() or not plugin_path.exists():
                continue
            raw = yaml.safe_load(manifest_path.read_text()) or {}
            errors = validate_manifest(raw, entry)
            if errors:
                raise ValueError(f"Invalid manifest for {entry.name}: {'; '.join(errors)}")
            manifest = PluginManifest(**raw)
            module = importlib.import_module(f"plugins.{entry.name}.plugin")
            plugin = module.build_plugin()
            setattr(plugin, "manifest", manifest)
            self._plugins[manifest.name] = plugin
            self._manifests[manifest.name] = manifest
            self._health[manifest.name] = health_status(manifest.required_binaries)
            count += 1
        return count

    def get(self, name: str):
        return self._plugins.get(name)

    def manifest_for(self, name: str) -> Optional[PluginManifest]:
        return self._manifests.get(name)

    def all(self) -> Dict[str, object]:
        return dict(self._plugins)

    def manifests(self) -> Dict[str, PluginManifest]:
        return dict(self._manifests)

    def health(self, name: str) -> Dict[str, object]:
        return dict(self._health.get(name, {"healthy": False, "missing_binaries": ["unregistered"]}))

    def plugins_by_capability(self, capability: str) -> List[object]:
        ranked: list[tuple[float, object]] = []
        for name, manifest in self._manifests.items():
            if capability not in manifest.capabilities:
                continue
            if not self.health(name).get("healthy", False):
                continue
            ranked.append((manifest.confidence_weight, self._plugins[name]))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [plugin for _, plugin in ranked]

    def plugin_name_for_capability(self, capability: str) -> Optional[str]:
        plugins = self.plugins_by_capability(capability)
        if not plugins:
            return None
        plugin = plugins[0]
        return getattr(plugin, "name", None)


class PluginRegistry:
    """Compatibility registry that loads enterprise structured plugins."""

    def __init__(self):
        self._enterprise = EnterprisePluginRegistry()
        self._plugins: Dict[str, object] = {}
        self._manifests: Dict[str, PluginManifest] = {}

    def load_from_dir(self, directory: Path) -> int:
        repo_root = directory.resolve().parents[1]
        enterprise_root = repo_root / "plugins"
        if enterprise_root.exists():
            count = self._enterprise.load_from_root(enterprise_root)
            self._plugins.update(self._enterprise.all())
            self._manifests.update(self._enterprise.manifests())
            return count
        return 0

    def get(self, name: str):
        return self._plugins.get(name)

    def all(self) -> Dict[str, object]:
        return dict(self._plugins)

    def available_map(self) -> Dict[str, bool]:
        return {name: bool(self._enterprise.health(name).get("healthy", False)) for name in self._plugins}

    def info(self) -> list:
        return [
            {
                "name": plugin.name,
                "desc": getattr(plugin, "description", ""),
                "category": getattr(plugin, "category", "util"),
                "available": bool(self._enterprise.health(name).get("healthy", False)),
                "capabilities": list(getattr(getattr(plugin, "manifest", None), "capabilities", [])),
            }
            for name, plugin in self._plugins.items()
        ]

    def manifest_for(self, name: str):
        return self._manifests.get(name)

    def health(self, name: str) -> Dict[str, object]:
        return self._enterprise.health(name)

    def plugin_name_for_capability(self, capability: str) -> Optional[str]:
        return self._enterprise.plugin_name_for_capability(capability)
