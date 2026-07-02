"""ORACLE Plugin — http  (plugins/http.py)"""
from __future__ import annotations
import shlex
from typing import Any, Dict
from .base import ToolPlugin


class HttpPlugin(ToolPlugin):
    name = "http"
    description = "Single HTTP request — grab status, headers, body preview"
    category = "recon"
    requires_binary = "curl"

    def build(self, target: str, args: Dict[str, Any]) -> str:
        port = args.get("port", 80)
        path = args.get("path", "/")
        method = args.get("method", "GET").upper()
        scheme = "https" if str(port) in ("443", "8443") else "http"
        hdrs = str(args.get("headers", "")).strip()
        data = str(args.get("data", "")).strip()

        argv = [
            "curl",
            "-sk",
            "--max-time",
            "15",
            "-D",
            "-",
            "-w",
            "\\n---STATS---\\n%{http_code} %{size_download} %{time_total}",
            "-o",
            "/dev/null",
        ]

        if hdrs:
            argv.extend(["-H", hdrs])
        if method == "POST":
            argv.extend(["-X", "POST"])
            if data:
                argv.extend(["-d", data])
        argv.append(f"{scheme}://{target}:{port}{path}")
        return " ".join(shlex.quote(str(item)) for item in argv)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Returns a strict contract:
            {
                "status": "ok" | "error",
                "data": {
                    "status_code": int,
                    "headers": Dict[str, str],
                    "server": str,
                    "powered": str
                },
                "error": str
            }
        """
        try:
            headers: Dict[str, str] = {}
            status_code = 0

            for line in stdout.splitlines():
                if line.startswith("HTTP/"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except ValueError:
                            pass
                elif ":" in line and not line.startswith("---"):
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            return {
                "status": "ok",
                "data": {
                    "status_code": status_code,
                    "headers": headers,
                    "server": headers.get("server", ""),
                    "powered": headers.get("x-powered-by", ""),
                },
                "error": "",
            }
        except Exception as e:
            return {
                "status": "error",
                "data": {
                    "status_code": 0,
                    "headers": {},
                    "server": "",
                    "powered": "",
                },
                "error": f"HttpPlugin parse error: {e}",
            }
