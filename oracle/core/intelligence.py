"""
ORACLE — CVE Intelligence Engine  (oracle/core/intelligence.py)

Tier 1: Offline, bundled mapping (default, OPSEC-safe).
Tier 2: Optional online enrichment (non-blocking background worker).
"""

from __future__ import annotations

import gzip
import json
import queue
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import requests


def _default_offline_db_path() -> Path:
    # Prefer operator-updated DB in ~/.oracle (no reinstall needed).
    user = Path.home() / ".oracle" / "cve_offline.json"
    if user.exists():
        return user

    base = Path(__file__).resolve().parent.parent / "data"
    gz = base / "cve_offline.json.gz"
    js = base / "cve_offline.json"
    return gz if gz.exists() else js


@dataclass(frozen=True)
class OnlineQuery:
    version: str
    host: str
    port: int
    protocol: str


class IntelligenceEngine:
    """
    Hybrid CVE enrichment engine.

    - `enrich_offline()` is immediate and never blocks.
    - `enqueue_online()` is fire-and-forget and never blocks the caller.
    - Online failures/timeouts are swallowed (safe fallback).
    """

    def __init__(
        self,
        *,
        offline_db_path: Optional[Path] = None,
        online_enabled: bool = False,
        nvd_api_key: str = "",
        vulners_api_key: str = "",
        update_cb: Optional[Callable[[dict[str, Any]], None]] = None,
        queue_max: int = 256,
        online_timeout_s: float = 5.0,
    ):
        self.offline_db_path = offline_db_path or _default_offline_db_path()
        self.online_enabled = bool(online_enabled)
        self.nvd_api_key = nvd_api_key
        self.vulners_api_key = vulners_api_key
        self.update_cb = update_cb
        self.queue_max = max(1, int(queue_max))
        self.online_timeout_s = float(online_timeout_s)

        self._offline = self._load_offline_db(self.offline_db_path)

        self._q: "queue.Queue[OnlineQuery]" = queue.Queue(maxsize=self.queue_max)
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

        if self.online_enabled:
            self._t = threading.Thread(target=self._worker, daemon=True, name="oracle-cve-intel")
            self._t.start()

    # ── Tier 1: Offline ─────────────────────────────────────────────────────

    def enrich_offline(self, *, version: str) -> dict[str, Any]:
        v = (version or "").strip()
        if not v:
            return {"cves": [], "sources": []}

        v_l = v.lower()
        cves: list[str] = []
        cvss: Optional[float] = None

        for row in self._offline:
            for pat in row.get("patterns", []):
                try:
                    if re.search(pat, v_l):
                        cves.extend(row.get("cves", []))
                        if cvss is None and isinstance(row.get("cvss"), (int, float)):
                            cvss = float(row["cvss"])
                        break
                except re.error:
                    # Ignore bad patterns; offline DB must never crash runtime.
                    continue

        # De-dupe while preserving order.
        seen = set()
        cves = [c for c in cves if not (c in seen or seen.add(c))]

        out: dict[str, Any] = {"cves": cves, "sources": (["offline"] if cves else [])}
        if cvss is not None:
            out["cvss"] = cvss
        return out

    def _load_offline_db(self, path: Path) -> list[dict[str, Any]]:
        try:
            if path.exists() and path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            if path.exists() and path.suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
        except Exception:
            pass
        return []

    # ── Tier 2: Online ──────────────────────────────────────────────────────

    def enqueue_online(self, *, version: str, host: str, port: int, protocol: str) -> bool:
        if not self.online_enabled:
            return False
        v = (version or "").strip()
        if not v:
            return False
        try:
            self._q.put_nowait(OnlineQuery(version=v, host=host, port=int(port), protocol=protocol))
            return True
        except queue.Full:
            return False

    def close(self):
        self._stop.set()
        if self._t and self._t.is_alive():
            self._t.join(timeout=1.0)

    def _worker(self):
        while not self._stop.is_set():
            try:
                q = self._q.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                info = self._online_lookup(q.version)
                if info and info.get("cves"):
                    payload = {
                        "host": q.host,
                        "port": q.port,
                        "protocol": q.protocol,
                        "version": q.version,
                        "cves": info.get("cves", []),
                        "cvss": info.get("cvss"),
                        "sources": info.get("sources", []),
                    }
                    if self.update_cb:
                        try:
                            self.update_cb(payload)
                        except Exception:
                            pass
            except Exception:
                # Never let the background worker crash the process.
                pass
            finally:
                try:
                    self._q.task_done()
                except Exception:
                    pass

    def _online_lookup(self, version: str) -> dict[str, Any]:
        """
        Best-effort online enrichment.
        Tries Vulners (if key set) then NVD (if key set or anonymous).

        Returns: {"cves":[...], "cvss": float|None, "sources":[...]}
        """
        v = (version or "").strip()
        if not v:
            return {"cves": [], "sources": []}

        # Small heuristic to keep queries short and reduce rate-limit pressure.
        query = re.sub(r"[^a-zA-Z0-9\\.\\-_/ ]+", " ", v)[:120].strip()

        if self.vulners_api_key:
            res = self._lookup_vulners(query)
            if res.get("cves"):
                return res

        return self._lookup_nvd(query)

    def _lookup_vulners(self, query: str) -> dict[str, Any]:
        try:
            # Vulners Lucene endpoint (best-effort). We only need CVE IDs.
            url = "https://vulners.com/api/v3/search/lucene/"
            r = requests.post(
                url,
                json={"query": query, "apiKey": self.vulners_api_key},
                timeout=self.online_timeout_s,
            )
            if r.status_code != 200:
                return {"cves": [], "sources": []}
            body = r.json()
            docs = (body.get("data") or {}).get("search") or []
            cves: list[str] = []
            for d in docs[:20]:
                cve = d.get("_source", {}).get("cvelist") or d.get("_source", {}).get("id")
                if isinstance(cve, list):
                    cves.extend([x for x in cve if isinstance(x, str) and x.startswith("CVE-")])
                elif isinstance(cve, str) and cve.startswith("CVE-"):
                    cves.append(cve)
            cves = list(dict.fromkeys(cves))
            return {"cves": cves, "sources": (["vulners"] if cves else [])}
        except Exception:
            return {"cves": [], "sources": []}

    def _lookup_nvd(self, query: str) -> dict[str, Any]:
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            r = requests.get(
                url,
                params={"keywordSearch": query, "resultsPerPage": 20},
                headers=headers,
                timeout=self.online_timeout_s,
            )
            if r.status_code != 200:
                return {"cves": [], "sources": []}

            body = r.json()
            vulns = body.get("vulnerabilities") or []
            cves: list[str] = []
            cvss: Optional[float] = None
            for v in vulns:
                cve = ((v.get("cve") or {}).get("id")) or ""
                if isinstance(cve, str) and cve.startswith("CVE-"):
                    cves.append(cve)

                # best-effort metric extraction
                metrics = (v.get("cve") or {}).get("metrics") or {}
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    m = metrics.get(k)
                    if isinstance(m, list) and m:
                        score = (((m[0] or {}).get("cvssData") or {}).get("baseScore"))
                        if isinstance(score, (int, float)):
                            cvss = float(score)
                            break
                    if cvss is not None:
                        break

            cves = list(dict.fromkeys(cves))
            out: dict[str, Any] = {"cves": cves, "sources": (["nvd"] if cves else [])}
            if cvss is not None:
                out["cvss"] = cvss
            return out
        except Exception:
            return {"cves": [], "sources": []}
