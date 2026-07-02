"""
ORACLE — Plugin Base & Registry  (plugins/base.py)
Drop a new file ending in _plugin.py into plugins/ to auto-register it.
"""
from __future__ import annotations
import importlib.util
import inspect
import logging
import warnings
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from plugins.registry import EnterprisePluginRegistry

warnings.warn(
    "oracle.plugins.base is deprecated. Use plugins.registry instead.",
    DeprecationWarning,
    stacklevel=2,
)

log = logging.getLogger("oracle.plugins")


class ToolPlugin(ABC):
    """
    Base class for all ORACLE tool plugins.

    Subclass this and set:
      name            — unique tool identifier string
      description     — one-line description
      category        — recon | web | util
      requires_binary — binary name to check availability (or None)
    """

    name: str = "base"
    description: str = ""
    category: str = "util"
    requires_binary: Optional[str] = None

    @abstractmethod
    def build(self, target: str, args: Dict[str, Any]) -> str:
        """Return the shell command to execute."""
        ...

    @abstractmethod
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse raw output into a structured dict."""
        ...

    @staticmethod
    def available(binary: Optional[str]) -> bool:
        if binary is None:
            return True
        import shutil
        return shutil.which(binary) is not None

    def __repr__(self) -> str:
        return f"<Plugin:{self.name}>"


# ── Registry ──────────────────────────────────────────────────────────────────

class PluginRegistry:
    """Auto-discovers and stores all ToolPlugin subclasses."""

    def __init__(self):
        self._plugins: Dict[str, ToolPlugin] = {}
        self._manifests: Dict[str, object] = {}
        self._enterprise = EnterprisePluginRegistry()

    def load_from_dir(self, directory: Path) -> int:
        """Load plugins from the enterprise root first, then legacy file plugins."""
        count = 0
        repo_root = directory.resolve().parents[1]
        enterprise_root = repo_root / "plugins"
        if enterprise_root.exists():
            enterprise_count = self._enterprise.load_from_root(enterprise_root)
            for name, plugin in self._enterprise.all().items():
                self._plugins[name] = plugin
                self._manifests[name] = self._enterprise.manifest_for(name)
            count += enterprise_count

        # External user plugins: load from file
        skip = {"base", "__init__", "nmap", "http", "fuzz"}
        for py in directory.glob("*.py"):
            if py.stem in skip:
                continue
            try:
                spec = importlib.util.spec_from_file_location(py.stem, py)
                if spec is None or spec.loader is None:
                    raise RuntimeError("spec/loader unavailable")
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(cls, ToolPlugin)
                            and cls is not ToolPlugin
                            and getattr(cls, "name", "base") != "base"):
                        self._plugins[cls.name] = cls()
                        count += 1
            except Exception as e:
                log.warning("Plugin load error (%s): %s", py.name, e)
        return count

    def get(self, name: str) -> Optional[ToolPlugin]:
        return self._plugins.get(name)

    def all(self) -> Dict[str, ToolPlugin]:
        return dict(self._plugins)

    def available_map(self) -> Dict[str, bool]:
        return {n: ToolPlugin.available(p.requires_binary) for n, p in self._plugins.items()}

    def info(self) -> list:
        return [
            {"name": p.name, "desc": p.description,
             "category": p.category,
             "available": ToolPlugin.available(p.requires_binary),
             "capabilities": list(getattr(getattr(p, "manifest", None), "capabilities", []))}
            for p in self._plugins.values()
        ]

    def manifest_for(self, name: str):
        return self._manifests.get(name)

    def health(self, name: str) -> Dict[str, object]:
        return self._enterprise.health(name)

    def plugin_name_for_capability(self, capability: str) -> Optional[str]:
        return self._enterprise.plugin_name_for_capability(capability)
