"""Enterprise nmap parser adapter."""

from oracle.plugins.nmap import NmapPlugin as LegacyNmapPlugin


class NmapParser:
    def __init__(self):
        self._legacy = LegacyNmapPlugin()

    def parse(self, stdout: str, stderr: str):
        return self._legacy.parse(stdout, stderr)

