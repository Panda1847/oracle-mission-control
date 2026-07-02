import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from plugins.registry import EnterprisePluginRegistry


def test_enterprise_registry_loads_manifests():
    registry = EnterprisePluginRegistry()
    count = registry.load_from_root(Path(__file__).resolve().parents[2] / "plugins")
    assert count == 3
    assert registry.manifest_for("nmap").capabilities
    assert registry.manifest_for("http").parser_schema == "schema.json"


def test_plugins_are_ranked_by_capability():
    registry = EnterprisePluginRegistry()
    registry.load_from_root(Path(__file__).resolve().parents[2] / "plugins")
    names = [plugin.name for plugin in registry.plugins_by_capability("http_probe")]
    assert names == ["http"]
