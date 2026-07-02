"""Future policy-facing scope guard wrapper."""

from __future__ import annotations

from oracle.runtime.safety import SafetyValidator


class ScopeGuard:
    """Compatibility wrapper around the existing safety validator."""

    def __init__(self, scope: list[str]):
        self.validator = SafetyValidator(scope)

    def validate(self, action, command: str):
        return self.validator.validate(action, command)

    def in_scope(self, target: str) -> bool:
        return self.validator.in_scope(target)

    def scope_summary(self) -> str:
        return self.validator.scope_summary()
