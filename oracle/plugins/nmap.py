"""ORACLE Plugin — nmap  (plugins/nmap.py)"""
from __future__ import annotations
import re
import shlex
from typing import Any, Dict, List
from .base import ToolPlugin


class NmapPlugin(ToolPlugin):
    name = "nmap"
    description = "TCP port scan with service/version detection"
    category = "recon"
    requires_binary = "nmap"

    # Common port set covering most services encountered in lab environments
    DEFAULT_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,"
        "993,995,1723,3306,3389,5900,8080,8443,8888"
    )

    def build(self, target: str, args: Dict[str, Any]) -> str:
        ports = str(args.get("ports", self.DEFAULT_PORTS)).replace(" ", "")
        timing = str(args.get("timing", "T4"))
        extra = str(args.get("extra", "")).strip()
        argv = ["nmap", "-sV", "--open", f"-{timing}", "-p", ports]
        if extra:
            argv.extend(shlex.split(extra))
        argv.append(str(target))
        return " ".join(shlex.quote(item) for item in argv)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Returns a strict contract:
            {
                "status": "ok" | "error",
                "data": {
                    "ports": List[Dict],
                    "os_guess": str,
                    "raw": str
                },
                "error": str
            }
        """
        try:
            ports: List[Dict[str, Any]] = []
            os_guess = ""

            for line in stdout.splitlines():
                # "80/tcp   open  http    Apache httpd 2.4.41"
                m = re.search(r"(\d+)/(tcp|udp)\s+open\s+([\w\-]+)\s*(.*)", line)
                if m:
                    ports.append(
                        {
                            "port": int(m.group(1)),
                            "protocol": m.group(2),
                            "service": m.group(3).strip(),
                            "version": m.group(4).strip(),
                            "state": "open",
                        }
                    )
                m_os = re.search(r"OS details:\s*(.+)", line)
                if m_os:
                    os_guess = m_os.group(1).strip()

            return {
                "status": "ok",
                "data": {
                    "ports": ports,
                    "os_guess": os_guess,
                    "raw": stdout[:3000],
                },
                "error": "",
            }
        except Exception as e:
            return {
                "status": "error",
                "data": {"ports": [], "os_guess": "", "raw": ""},
                "error": f"NmapPlugin parse error: {e}",
            }
