"""
ORACLE — Safety Validator  (runtime/safety.py)
Two-layer protection: scope enforcement + destructive-command blocklist.
Every command passes through here before execution.
"""
from __future__ import annotations
import ipaddress
import socket
from typing import List, Tuple

from ..core.models import Action


class SafetyValidator:
    """
    Layer 1 — Scope check:   target must be inside declared mission scope.
    Layer 2 — Blocklist:     hard-blocked shell patterns are never run.
    Layer 3 — Tool whitelist: only registered tool names are allowed.
    """

    # ── Hard-blocked shell patterns (never executed regardless of scope) ──────
    BLOCKED_PATTERNS: Tuple[str, ...] = (
        "rm -rf /",
        "rm -rf ~",
        "mkfs",
        "dd if=",
        ":(){:|:",          # fork bomb
        "chmod -R 777 /",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "> /dev/sd",
        "fdisk /dev/",
        "wipefs",
        "> /etc/passwd",
        "> /etc/shadow",
        "curl | bash",
        "curl | sh",
        "wget -O- | bash",
    )

    # ── Allowed tools ─────────────────────────────────────────────────────────
    ALLOWED_TOOLS = {"nmap", "http", "fuzz"}

    def __init__(self, scope: List[str], strict: bool = True):
        self.strict = strict
        self._nets: List[ipaddress.IPv4Network] = []
        self._hosts: set = set()

        for s in scope:
            try:
                self._nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                self._hosts.add(s.lower())

    # ── Public interface ──────────────────────────────────────────────────────

    def validate(self, action: Action, command: str) -> Tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        False = BLOCK the command.
        """
        # 1. Tool whitelist
        if action.tool not in self.ALLOWED_TOOLS:
            return False, f"Tool '{action.tool}' not in whitelist {self.ALLOWED_TOOLS}"

        # 2. Scope check
        if not self._in_scope(action.target):
            return False, f"Target '{action.target}' is OUT OF SCOPE"

        # 3. Blocklist
        cmd_lower = command.lower()
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.lower() in cmd_lower:
                return False, f"Blocked pattern: '{pattern}'"

        return True, "OK"

    def in_scope(self, target: str) -> bool:
        return self._in_scope(target)

    def scope_summary(self) -> str:
        parts = [str(n) for n in self._nets] + sorted(self._hosts)
        return ", ".join(parts) if parts else "Unrestricted"

    # ── Private ───────────────────────────────────────────────────────────────

    def _in_scope(self, target: str) -> bool:
        # Always allow loopback
        if target in ("localhost", "127.0.0.1", "::1", "local"):
            return True
        # No scope defined = allow (demo/test mode)
        if not self._nets and not self._hosts:
            return True
        # Try IP match
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self._nets)
        except ValueError:
            pass
        # Hostname match
        lowered = target.lower()
        if lowered in self._hosts:
            return True
        # Hostname/IP mixed scope support:
        # if scope is CIDR-based and target is hostname, resolve and check all answers.
        if self._nets:
            try:
                infos = socket.getaddrinfo(target, None)
            except socket.gaierror:
                return False
            except Exception:
                return False
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                candidate = str(sockaddr[0])
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if any(ip in net for net in self._nets):
                    return True
        return False
