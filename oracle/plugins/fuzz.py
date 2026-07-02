"""ORACLE Plugin — fuzz  (plugins/fuzz.py)
Web directory/path enumeration using gobuster or ffuf (whichever is present).
"""
from __future__ import annotations
import re
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, List
from .base import ToolPlugin


class FuzzPlugin(ToolPlugin):
    name = "fuzz"
    description = "Web directory enumeration (gobuster / ffuf)"
    category = "web"
    requires_binary = None  # checked dynamically below

    # Ordered wordlist preference
    WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/dict/words",
    ]

    def _wordlist(self, name: str = "common") -> str:
        for wl in self.WORDLISTS:
            if Path(wl).exists():
                return wl
        return self.WORDLISTS[0]  # best-effort even if not present

    def _backend(self) -> str:
        """Return 'gobuster', 'ffuf', or 'none'."""
        if shutil.which("gobuster"):
            return "gobuster"
        if shutil.which("ffuf"):
            return "ffuf"
        return "none"

    def build(self, target: str, args: Dict[str, Any]) -> str:
        port = args.get("port", 80)
        exts = args.get("extensions", "php,html,txt")
        threads = args.get("threads", 20)
        wl_name = args.get("wordlist", "common")
        wordlist = self._wordlist(wl_name)
        scheme = "https" if str(port) in ("443", "8443") else "http"
        url = f"{scheme}://{target}:{port}/"

        backend = self._backend()

        if backend == "gobuster":
            argv = [
                "gobuster",
                "dir",
                "-u",
                url,
                "-w",
                wordlist,
                "-t",
                str(threads),
                "-x",
                str(exts),
                "-q",
                "--no-error",
            ]
            return " ".join(shlex.quote(str(item)) for item in argv)
        elif backend == "ffuf":
            argv = [
                "ffuf",
                "-u",
                f"{url}FUZZ",
                "-w",
                wordlist,
                "-t",
                str(threads),
                "-s",
                "-mc",
                "200,301,302,403",
            ]
            return " ".join(shlex.quote(str(item)) for item in argv)
        else:
            argv = [
                "curl",
                "-sk",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code} %{url_effective}\\n",
                url,
            ]
            return " ".join(shlex.quote(str(item)) for item in argv)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Always return a dict with the keys:
            - status:   "ok" if parsing succeeded, otherwise "error"
            - data:     a dict containing the parsed information (paths, interesting, count)
            - error:    an error message string if something went wrong, else empty string
        """
        try:
            paths: List[Dict[str, Any]] = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # gobuster: "/admin                 (Status: 200) [Size: 1234]"
                m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)", line)
                if m:
                    paths.append({"path": m.group(1), "status": int(m.group(2))})
                    continue
                # ffuf: "/admin"  (plain path output in -s mode)
                if line.startswith("/"):
                    paths.append({"path": line, "status": 0})

            interesting = [p for p in paths if p["status"] in (200, 301, 302, 403, 0)]

            return {
                "status": "ok",
                "data": {
                    "paths": paths,
                    "interesting": interesting,
                    "count": len(paths),
                },
                "error": "",
            }
        except Exception as e:
            # Ensure a predictable structure even on unexpected failures
            return {
                "status": "error",
                "data": {"paths": [], "interesting": [], "count": 0},
                "error": f"FuzzPlugin parse error: {e}",
            }
