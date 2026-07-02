"""Enterprise fuzz plugin adapter."""

from oracle.plugins.fuzz import FuzzPlugin as LegacyFuzzPlugin

from .parser import FuzzParser


class EnterpriseFuzzPlugin(LegacyFuzzPlugin):
    def __init__(self):
        super().__init__()
        self._parser = FuzzParser()

    def parse(self, stdout: str, stderr: str):
        return self._parser.parse(stdout, stderr)


def build_plugin():
    return EnterpriseFuzzPlugin()

