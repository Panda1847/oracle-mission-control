from core.ai.model_router import ModelRouter


class _Client:
    def __init__(self, ready: bool):
        self.ready = ready


class _Ollama:
    def __init__(self, ready: bool):
        self.ready = ready


def test_model_router_selects_ollama_when_backend_forced():
    remote = _Client(ready=True)
    ollama = _Ollama(ready=True)
    router = ModelRouter(
        client=remote,
        config={"advisor": {"backend": "ollama"}, "ollama": {"enabled": True}},
        env={},
        ollama_client=ollama,
    )
    assert router.active() is ollama


def test_model_router_auto_uses_ollama_when_remote_not_ready():
    remote = _Client(ready=False)
    ollama = _Ollama(ready=True)
    router = ModelRouter(
        client=remote,
        config={"advisor": {"backend": "auto"}, "ollama": {"enabled": True}},
        env={},
        ollama_client=ollama,
    )
    assert router.active() is ollama


def test_model_router_env_override_to_deterministic():
    remote = _Client(ready=True)
    ollama = _Ollama(ready=True)
    router = ModelRouter(
        client=remote,
        config={"advisor": {"backend": "auto"}, "ollama": {"enabled": True}},
        env={"ORACLE_AI_BACKEND": "deterministic"},
        ollama_client=ollama,
    )
    assert router.active() is router.fallback()


def test_model_router_selects_council_when_backend_forced():
    remote = _Client(ready=True)
    ollama = _Ollama(ready=False)
    router = ModelRouter(
        client=remote,
        config={"advisor": {"backend": "council"}, "ollama": {"enabled": True}},
        env={},
        ollama_client=ollama,
    )
    assert router.active() is router.council
