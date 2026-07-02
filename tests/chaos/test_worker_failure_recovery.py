import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.orchestrator.dispatcher import Dispatcher
from oracle.core.models import Action
from oracle.plugins.base import PluginRegistry, ToolPlugin
from oracle.runtime.executor import Executor


class EchoPlugin(ToolPlugin):
    name = "echo"
    description = "echo plugin"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "printf 'local-ok'"

    def parse(self, stdout, stderr):
        return {"message": stdout}


def test_dispatcher_recovers_when_remote_worker_dies(monkeypatch):
    registry = PluginRegistry()
    registry._plugins["echo"] = EchoPlugin()
    executor = Executor(registry)
    dispatcher = Dispatcher(executor)
    action = Action(tool="echo", target="127.0.0.1", args={}, timeout=3, phase="DISCOVERY")

    dispatcher.register_remote_worker("dead-remote", "http://127.0.0.1:65500", ["echo"])

    def boom(*args, **kwargs):
        raise TimeoutError("worker died mid-mission")

    monkeypatch.setattr(dispatcher, "_dispatch_remote", boom)
    try:
        result = dispatcher.dispatch(action, command="printf 'local-ok'")
        assert result.returncode == 0
        assert result.stdout == "local-ok"
        assert result.parsed["_worker_id"] == "local-node"
    finally:
        dispatcher.shutdown()

