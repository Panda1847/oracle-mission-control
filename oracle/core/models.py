"""
ORACLE — Core Data Models
All shared dataclasses used throughout the system.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _uid() -> str:
    return uuid.uuid4().hex[:8]


@dataclass
class Action:
    tool: str
    target: str
    args: Dict[str, Any]
    confidence: float = 0.7
    reasoning: str = ""
    phase: str = "recon"
    timeout: int = 60
    requires_approval: bool = False
    expected: str = ""
    agent_id: str = "oracle"


@dataclass
class ActionResult:
    action: Action
    stdout: str
    stderr: str
    returncode: int
    duration: float
    parsed: Dict[str, Any] = field(default_factory=dict)
    timeout_hit: bool = False
    binary_missing: bool = False
    parse_valid: bool = True
    quarantined: bool = False
    error_kind: str = ""
    command_fingerprint: str = ""
    ts: str = field(default_factory=_ts)

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def short_summary(self) -> str:
        status = "✓" if self.success else "✗"
        flags = []
        if self.timeout_hit:
            flags.append("timeout")
        if self.binary_missing:
            flags.append("binary-missing")
        if self.quarantined:
            flags.append("quarantined")
        flag_suffix = f" [{'|'.join(flags)}]" if flags else ""
        return (
            f"[{status}] {self.action.tool} → {self.action.target} "
            f"({self.duration:.1f}s) rc={self.returncode}{flag_suffix}"
        )


@dataclass
class Finding:
    fid: str = field(default_factory=_uid)
    severity: str = "INFO"        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str = ""
    description: str = ""
    host: str = ""
    port: int = 0
    evidence: str = ""
    plugin: str = ""
    ts: str = field(default_factory=_ts)

    RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    @property
    def rank(self) -> int:
        return self.RANK.get(self.severity, 0)


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    cves: List[str] = field(default_factory=list)
    cvss: Optional[float] = None
    exploitability: Optional[str] = None
    cve_sources: List[str] = field(default_factory=list)


@dataclass
class HostRecord:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    alive: bool = True
    ports: List[PortInfo] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def add_port(self, port: int, **kw) -> PortInfo:
        for p in self.ports:
            if p.port == port:
                for k, v in kw.items():
                    if v:
                        setattr(p, k, v)
                return p
        pi = PortInfo(port=port, **kw)
        self.ports.append(pi)
        return pi

    def open_ports(self) -> List[int]:
        return [p.port for p in self.ports if p.state == "open"]


@dataclass
class Mission:
    name: str
    scope: List[str]
    objective: str = "Identify all reachable services and vulnerabilities"
    profile: str = "normal"           # stealth | normal | aggressive
    phase: str = "recon"             # recon | enum | exploit | post | report
    status: str = "running"          # running | paused | complete | stopped
    iterations: int = 0
    max_iterations: int = 30
    started: str = field(default_factory=_ts)
    tags: List[str] = field(default_factory=list)
