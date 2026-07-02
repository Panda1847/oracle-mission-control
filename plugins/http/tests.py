from plugins.registry import EnterprisePluginRegistry


def test_http_manifest_loads(tmp_path=None):
    registry = EnterprisePluginRegistry()
    count = registry.load_from_root(__import__("pathlib").Path(__file__).resolve().parents[1])
    assert count >= 1
    assert registry.manifest_for("http") is not None

