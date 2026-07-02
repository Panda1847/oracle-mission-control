"""Plugin sandbox policy helpers."""

from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, Optional


@dataclass
class SandboxDecision:
    allowed: bool
    reason: str
    binary: str = ""

    def to_dict(self) -> Dict[str, str | bool]:
        return asdict(self)


class PluginSandbox:
    """Applies allowlists so one plugin cannot escape the enterprise execution envelope."""

    def __init__(self, allowed_binaries: Optional[Iterable[str]] = None):
        self.allowed_binaries = {str(binary) for binary in (allowed_binaries or []) if str(binary).strip()}

    def validate(self, command: str, required_binaries: Iterable[str] | None = None) -> SandboxDecision:
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            return SandboxDecision(False, f"invalid shell syntax: {exc}")
        if not tokens:
            return SandboxDecision(False, "empty command")
        binary = tokens[0]
        manifest_allowlist = {str(item) for item in (required_binaries or []) if str(item).strip()}
        allowlist = manifest_allowlist or self.allowed_binaries
        if allowlist and binary not in allowlist:
            return SandboxDecision(False, f"binary {binary} not permitted by sandbox", binary=binary)
        return SandboxDecision(True, "allowed", binary=binary)

