import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.core.models import Action
from oracle.plugins.base import PluginRegistry, ToolPlugin
from oracle.runtime.executor import Executor


class EchoPlugin(ToolPlugin):
    name = "echo"
    description = "echo plugin"
    category = "util"
    requires_binary = None

    def build(self, target, args):
        return "printf 'hello-from-go'"

    def parse(self, stdout, stderr):
        return {"message": stdout}


def test_executor_uses_go_runtime_when_available():
    reg = PluginRegistry()
    reg._plugins["echo"] = EchoPlugin()
    executor = Executor(reg)
    action = Action(tool="echo", target="127.0.0.1", args={}, timeout=10)

    result = executor.run(action)

    assert result.returncode == 0
    assert result.stdout == "hello-from-go"
    assert result.parsed["message"] == "hello-from-go"
