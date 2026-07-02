"""Enterprise http plugin adapter."""

from oracle.plugins.http import HttpPlugin as LegacyHttpPlugin

from .parser import HttpParser


class EnterpriseHttpPlugin(LegacyHttpPlugin):
    def __init__(self):
        super().__init__()
        self._parser = HttpParser()

    def parse(self, stdout: str, stderr: str):
        return self._parser.parse(stdout, stderr)


def build_plugin():
    return EnterpriseHttpPlugin()

