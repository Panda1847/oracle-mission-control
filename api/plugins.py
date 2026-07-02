"""Plugin control-plane serializers."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List


def _manifest_to_dict(manifest) -> Dict[str, Any]:
    if manifest is None:
        return {}
    if is_dataclass(manifest):
        return asdict(manifest)
    return dict(getattr(manifest, "__dict__", {}))


def plugin_snapshot(registry) -> List[Dict[str, Any]]:
    if registry is None:
        return []
    items: List[Dict[str, Any]] = []
    for name, plugin in registry.all().items():
        manifest = _manifest_to_dict(registry.manifest_for(name))
        health = registry.health(name)
        items.append(
            {
                "name": name,
                "description": getattr(plugin, "description", ""),
                "version": manifest.get("version", ""),
                "enabled": bool(health.get("healthy", False)),
                "binary_present": bool(health.get("healthy", False)),
                "health_status": "healthy" if health.get("healthy", False) else "degraded",
                "validator_attached": True,
                "manifest": manifest,
                "health": health,
            }
        )
    return items
