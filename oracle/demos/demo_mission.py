"""
ORACLE — Demo Mission  (demos/demo_mission.py)
Fully simulated mission. No API key, no real tools, no real network.
Populates the KnowledgeGraph with realistic data to showcase the full UI.
"""
from __future__ import annotations
import time
from typing import Generator, Dict

from ..memory.graph import KnowledgeGraph
from ..core.models import PortInfo

# ── Simulated data ────────────────────────────────────────────────────────────

DEMO_HOSTS = [
    {
        "ip": "192.168.56.101",
        "hostname": "target-web",
        "os_guess": "Linux Ubuntu 22.04",
        "ports": [
            {"port": 22,   "service": "ssh",   "version": "OpenSSH 8.9p1"},
            {"port": 80,   "service": "http",  "version": "Apache 2.4.52"},
            {"port": 443,  "service": "https", "version": "Apache/mod_ssl"},
            {"port": 3306, "service": "mysql", "version": "MySQL 8.0.30"},
        ],
    },
    {
        "ip": "192.168.56.102",
        "hostname": "target-smb",
        "os_guess": "Windows Server 2019",
        "ports": [
            {"port": 135, "service": "msrpc",      "version": "Microsoft RPC"},
            {"port": 445, "service": "smb",        "version": "Windows Server 2019"},
            {"port": 3389,"service": "rdp",        "version": "Microsoft RDP"},
        ],
    },
]

DEMO_FINDINGS = [
    {
        "severity": "HIGH",
        "title": "SMB signing disabled on 192.168.56.102",
        "description": "SMB signing not required — relay attacks possible.",
        "host": "192.168.56.102", "port": 445, "plugin": "nmap",
    },
    {
        "severity": "MEDIUM",
        "title": "Apache directory listing at /uploads/",
        "description": "Directory indexing exposes file structure.",
        "host": "192.168.56.101", "port": 80, "plugin": "fuzz",
    },
    {
        "severity": "MEDIUM",
        "title": "Sensitive path: /admin [HTTP 200]",
        "description": "Admin panel accessible without IP restriction.",
        "host": "192.168.56.101", "port": 80, "plugin": "fuzz",
    },
    {
        "severity": "LOW",
        "title": "RDP exposed to all interfaces",
        "description": "Port 3389 reachable with no IP allowlist.",
        "host": "192.168.56.102", "port": 3389, "plugin": "nmap",
    },
    {
        "severity": "INFO",
        "title": "Web server banner: Apache 2.4.52",
        "description": "Version disclosure in Server header.",
        "host": "192.168.56.101", "port": 80, "plugin": "http",
    },
]

DEMO_ACTIONS = [
    {
        "phase": "recon",
        "tool": "nmap",
        "target": "192.168.56.0/24",
        "thinking": "First I'll sweep the subnet to discover live hosts and open ports. A -sV scan on common ports gives me service banners.",
        "reasoning": "Initial recon — discover all live hosts and services.",
        "duration": 4.2,
    },
    {
        "phase": "recon",
        "tool": "nmap",
        "target": "192.168.56.101",
        "thinking": "101 has port 80 and 443 open. I'll do a deeper version scan to confirm Apache version and gather more service detail.",
        "reasoning": "Deep scan of web host — confirm version info.",
        "duration": 2.8,
    },
    {
        "phase": "enum",
        "tool": "http",
        "target": "192.168.56.101",
        "thinking": "Apache on 80 — let me grab the headers to confirm server version and check for security headers.",
        "reasoning": "HTTP header grab — check server version and security posture.",
        "duration": 0.4,
    },
    {
        "phase": "enum",
        "tool": "fuzz",
        "target": "192.168.56.101",
        "thinking": "Web server is running — time to enumerate directories. Looking for /admin, /uploads, /config, backup files.",
        "reasoning": "Directory fuzzing — find hidden paths and admin panels.",
        "duration": 8.1,
    },
    {
        "phase": "enum",
        "tool": "http",
        "target": "192.168.56.101",
        "thinking": "I found /admin returning 200. Let me probe it to see if it's protected or open.",
        "reasoning": "Probe /admin path — check if protected.",
        "duration": 0.3,
    },
    {
        "phase": "post",
        "tool": "nmap",
        "target": "192.168.56.102",
        "thinking": "The Windows host has 445 open. I'll run targeted nmap scripts to check SMB signing status.",
        "reasoning": "SMB enumeration on Windows host — check signing requirements.",
        "duration": 3.5,
    },
]


class DemoRunner:
    """
    Replays scripted demo events at configurable speed.
    Populates graph identically to a live mission.
    """

    def __init__(self, graph: KnowledgeGraph, speed: float = 1.0):
        self.graph = graph
        self.speed = speed

    def run(self) -> Generator[Dict, None, None]:
        yield {"type": "start", "msg": "🎬 ORACLE Demo — DemoNet v1"}
        time.sleep(0.5 * self.speed)

        # Phase: host discovery
        yield {"type": "phase", "phase": "recon"}
        for hdata in DEMO_HOSTS:
            h = self.graph.add_host(
                hdata["ip"],
                hostname=hdata["hostname"],
                os_guess=hdata["os_guess"],
            )
            for p in hdata["ports"]:
                h.add_port(p["port"], service=p["service"], version=p["version"])
            self.graph.save()
            yield {
                "type": "host_found",
                "ip": hdata["ip"],
                "hostname": hdata["hostname"],
                "ports": len(hdata["ports"]),
                "thinking": f"Discovered {hdata['ip']} ({hdata['hostname']}) — "
                            f"{len(hdata['ports'])} open ports",
            }
            time.sleep(0.8 * self.speed)

        # Phase: replay actions
        for i, act in enumerate(DEMO_ACTIONS):
            time.sleep(1.0 * self.speed)
            yield {
                "type": "action",
                "phase": act["phase"],
                "tool": act["tool"],
                "target": act["target"],
                "reasoning": act["reasoning"],
                "thinking": act["thinking"],
                "duration": act["duration"],
                "iteration": i + 1,
            }

        # Phase: add findings
        time.sleep(0.5 * self.speed)
        for fd in DEMO_FINDINGS:
            self.graph.add_finding(**fd)
            yield {"type": "finding", **fd}
            time.sleep(0.25 * self.speed)

        self.graph.save()
        time.sleep(0.5 * self.speed)
        yield {
            "type": "complete",
            "msg": f"Demo complete — {len(self.graph.hosts)} hosts, {len(self.graph.findings)} findings",
            "hosts": len(self.graph.hosts),
            "findings": len(self.graph.findings),
        }
