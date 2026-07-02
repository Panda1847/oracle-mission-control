import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.models import Action
from oracle.plugins.base import PluginRegistry, ToolPlugin
from oracle.runtime.executor import Executor
from core.orchestrator.dispatcher import Dispatcher
from workers.agent import WorkerAgent


class EchoPlugin(ToolPlugin):
    name = "echo"
    description = "echo plugin"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "printf 'worker-echo'"

    def parse(self, stdout, stderr):
        return {"message": stdout}


def test_dispatcher_remote_worker_callback_flow():
    reg = PluginRegistry()
    reg._plugins["echo"] = EchoPlugin()
    executor = Executor(reg)
    dispatcher = Dispatcher(executor)
    agent = WorkerAgent(worker_id="node-1", capabilities=["echo"], shared_secret=dispatcher.shared_secret)
    agent.start()
    try:
        dispatcher.register_remote_worker("node-1", agent.endpoint, ["echo"])
        action = Action(tool="echo", target="127.0.0.1", args={}, timeout=10, phase="DISCOVERY")
        result = dispatcher.dispatch(action, command="printf 'worker-echo'")
        assert result.returncode == 0
        assert result.stdout == "worker-echo"
        assert result.parsed["_worker_id"] == "node-1"
    finally:
        dispatcher.shutdown()
        agent.stop()


def test_dispatcher_falls_back_to_local_when_remote_unavailable():
    reg = PluginRegistry()
    reg._plugins["echo"] = EchoPlugin()
    executor = Executor(reg)
    dispatcher = Dispatcher(executor)
    try:
        dispatcher.register_remote_worker("dead-node", "http://127.0.0.1:65500", ["echo"])
        action = Action(tool="echo", target="127.0.0.1", args={}, timeout=3, phase="DISCOVERY")
        result = dispatcher.dispatch(action, command="printf 'worker-echo'")
        assert result.returncode == 0
        assert result.stdout == "worker-echo"
        assert result.parsed["_worker_id"] == "local-node"
    finally:
        dispatcher.shutdown()
