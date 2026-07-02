from core.ai.ollama_client import OllamaAdvisorClient


class _Mission:
    name = "m1"
    scope = ["127.0.0.1"]
    objective = "test"
    profile = "normal"
    iterations = 1
    max_iterations = 5


class _Graph:
    @staticmethod
    def summary():
        return "HOST 127.0.0.1 ports: 22"


def test_ollama_client_decide_parses_json(monkeypatch):
    client = OllamaAdvisorClient(model="llama3.2:3b", enabled=True)
    monkeypatch.setattr(client, "_is_ready", lambda refresh=False: True)

    def _fake_request(url, payload=None, timeout=None):
        if url.endswith("/api/generate"):
            return {
                "response": (
                    '{"reasoning":"scan localhost","action":{"tool":"nmap","target":"127.0.0.1","args":{"ports":"22,80"}},'
                    '"confidence":0.82,"expected":"open ports"}'
                )
            }
        return {"models": [{"name": "llama3.2:3b"}]}

    monkeypatch.setattr(client, "_request_json", _fake_request)
    decision = client.decide(_Mission(), _Graph(), "context")
    assert decision["action"]["tool"] == "nmap"
    assert decision["action"]["target"] == "127.0.0.1"


def test_ollama_client_returns_stop_reason_on_malformed_json(monkeypatch):
    client = OllamaAdvisorClient(model="llama3.2:3b", enabled=True)
    monkeypatch.setattr(client, "_is_ready", lambda refresh=False: True)
    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"response": "not-json"})
    decision = client.decide(_Mission(), _Graph(), "context")
    assert "stop_reason" in decision
