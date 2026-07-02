"""Enterprise nmap plugin adapter."""

from oracle.plugins.nmap import NmapPlugin as LegacyNmapPlugin

from .parser import NmapParser


class EnterpriseNmapPlugin(LegacyNmapPlugin):
    def __init__(self):
        super().__init__()
        self._parser = NmapParser()

    def parse(self, stdout: str, stderr: str):
        return self._parser.parse(stdout, stderr)


def build_plugin():
    return EnterpriseNmapPlugin()

