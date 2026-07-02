"""Enterprise http parser adapter."""

from oracle.plugins.http import HttpPlugin as LegacyHttpPlugin


class HttpParser:
    def __init__(self):
        self._legacy = LegacyHttpPlugin()

    def parse(self, stdout: str, stderr: str):
        return self._legacy.parse(stdout, stderr)

