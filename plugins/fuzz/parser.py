"""Enterprise fuzz parser adapter."""

from oracle.plugins.fuzz import FuzzPlugin as LegacyFuzzPlugin


class FuzzParser:
    def __init__(self):
        self._legacy = LegacyFuzzPlugin()

    def parse(self, stdout: str, stderr: str):
        return self._legacy.parse(stdout, stderr)

