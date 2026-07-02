"""
ORACLE — Knowledge Graph  (memory/graph.py)
Thread-safe store for hosts, findings, and action history.
Populates itself by ingesting ActionResult objects from the executor.
"""
from __future__ import annotations
import threading
from dataclasses import asdict, fields
from typing import Callable, Dict, List, Optional, Any

from ..core.models import (
    Action, ActionResult, Finding, HostRecord, PortInfo, Mission
)
from ..memory.storage import Storage
from ..core.intelligence import IntelligenceEngine
from memory.graph_store import EvidenceGraphStore


class KnowledgeGraph:
    """
    Central intelligence store.
    All write operations are thread-safe (for multi-agent use).
    Fires optional event callbacks for real-time dashboard updates.
    """

    def __init__(
        self,
        mission_id: str,
        storage: Storage,
        event_cb: Optional[Callable] = None,
        intel: Optional[IntelligenceEngine] = None,
    ):
        self.mission_id = mission_id
        self._storage   = storage
        self._event_cb  = event_cb
        self._intel     = intel
        self._lock      = threading.RLock()
        self._evidence  = EvidenceGraphStore(
            self._storage.base_dir / f"{self.mission_id}_evidence.sqlite",
            mission_id=self.mission_id,
        )

        self.hosts:    Dict[str, HostRecord] = {}
        self.findings: List[Finding]         = []
        self.actions:  List[ActionResult]    = []
        self._directives: List[str]          = []
        self._chat: List[Dict[str, Any]]     = []
        self._reports: List[Dict[str, Any]]  = []

        self._load()

    def set_intel(self, intel: Optional[IntelligenceEngine]):
        self._intel = intel

    def apply_cve_update(self, update: Dict[str, Any]):
        """
        Apply online CVE enrichment for a specific host/port.
        This is safe to call from background threads.
        """
        host = (update.get("host") or "").strip()
        port = int(update.get("port") or 0)
        protocol = (update.get("protocol") or "tcp").strip()
        cves = update.get("cves") or []
        sources = update.get("sources") or []
        cvss = update.get("cvss")

        if not host or not port or not isinstance(cves, list):
            return

        with self._lock:
            hr = self.hosts.get(host)
            if not hr:
                return
            for pi in hr.ports:
                if pi.port == port and (pi.protocol or "tcp") == protocol:
                    pi.cves = list(dict.fromkeys([*pi.cves, *[c for c in cves if isinstance(c, str)]]))
                    pi.cve_sources = list(dict.fromkeys([*pi.cve_sources, *[s for s in sources if isinstance(s, str)]]))
                    if pi.cvss is None and isinstance(cvss, (int, float)):
                        pi.cvss = float(cvss)
                    self._evidence.add_evidence(
                        entity="cve",
                        value=f"{host}:{port}:{','.join(sorted(cves))}",
                        source_plugin="nmap",
                        observed_confidence=0.88,
                        payload={
                            "host": host,
                            "port": port,
                            "protocol": protocol,
                            "cves": cves,
                            "cvss": cvss,
                        },
                    )
                    break

        self._emit("host_updated", {"ip": host})

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self):
        data = self._storage.load(self.mission_id)
        if not data:
            return
        hosts = data.get("hosts", {})
        if not isinstance(hosts, dict):
            hosts = {}

        def _kw(cls, d: Any) -> dict:
            if not isinstance(d, dict):
                return {}
            allowed = {f.name for f in fields(cls)}
            return {k: v for k, v in d.items() if k in allowed}

        for ip, hd in hosts.items():
            if not isinstance(hd, dict):
                continue
            port_list = hd.get("ports", [])
            if not isinstance(port_list, list):
                port_list = []
            ports = [PortInfo(**_kw(PortInfo, p)) for p in port_list if isinstance(p, dict)]
            h = HostRecord(**_kw(HostRecord, {k: v for k, v in hd.items() if k != "ports"}))
            h.ports = ports
            self.hosts[ip] = h
        fl = data.get("findings", [])
        if not isinstance(fl, list):
            fl = []
        self.findings = [Finding(**_kw(Finding, f)) for f in fl if isinstance(f, dict)]

        raw_actions = data.get("actions", [])
        if not isinstance(raw_actions, list):
            raw_actions = []
        loaded_actions: List[ActionResult] = []
        for item in raw_actions:
            if not isinstance(item, dict):
                continue
            raw_action = item.get("action", {})
            if not isinstance(raw_action, dict):
                continue
            try:
                action = Action(**_kw(Action, raw_action))
                payload = _kw(ActionResult, {k: v for k, v in item.items() if k != "action"})
                loaded_actions.append(ActionResult(action=action, **payload))
            except Exception:
                continue
        self.actions = loaded_actions

        d = data.get("directives", [])
        self._directives = d if isinstance(d, list) else []
        c = data.get("chat", [])
        self._chat = c if isinstance(c, list) else []
        r = data.get("reports", [])
        self._reports = r if isinstance(r, list) else []

    def save(self):
        with self._lock:
            data = {
                "hosts": {
                    ip: {**{k: v for k, v in asdict(h).items() if k != "ports"},
                         "ports": [asdict(p) for p in h.ports]}
                    for ip, h in self.hosts.items()
                },
                "findings":   [asdict(f) for f in self.findings],
                "actions": [
                    {
                        **asdict(result),
                        "parsed": (result.parsed or {}),
                        "stdout": (result.stdout or "")[:20000],
                        "stderr": (result.stderr or "")[:10000],
                    }
                    for result in self.actions[-500:]
                ],
                "directives": self._directives,
                "chat":       self._chat[-200:],
                "reports":    self._reports[-30:],
            }
            self._storage.save(self.mission_id, data)

    def transaction_checkpoint(
        self,
        *,
        mission: Mission,
        action: Action | None,
        result: ActionResult | None,
        findings: List[Finding],
        audit_hash: str,
        state_hash: str,
        branch: str,
    ) -> bool:
        payload = {
            "mission": {
                "name": mission.name,
                "phase": mission.phase,
                "status": mission.status,
                "iterations": mission.iterations,
            },
            "action": asdict(action) if action is not None else {},
            "result": asdict(result) if result is not None else {},
            "findings": [asdict(finding) for finding in findings],
            "audit_hash": audit_hash,
            "state_hash": state_hash,
            "branch": branch,
            "stats": {
                "hosts": len(self.hosts),
                "findings": len(self.findings),
                "actions": len(self.actions),
            },
        }
        ok = self._storage.save(f"{self.mission_id}__checkpoint", payload)
        self.save()
        return ok

    # ── Host management ──────────────────────────────────────────────────────

    def add_host(self, ip: str, **kw) -> HostRecord:
        with self._lock:
            # If host exists, update only non-None attributes
            if ip in self.hosts:
                existing_host = self.hosts[ip]
                for k, v in kw.items():
                    if v is not None:
                        # Special handling for ports to prevent duplicates
                        if k == 'ports':
                            for new_port in v:
                                existing_host.add_port(
                                    new_port.port, 
                                    service=new_port.service, 
                                    version=new_port.version, 
                                    protocol=new_port.protocol
                                )
                        else:
                            setattr(existing_host, k, v)
                self._emit("host_updated", {"ip": ip})
                return existing_host

            # Create new host if not exists
            new_host = HostRecord(ip=ip, **kw)
            self.hosts[ip] = new_host
            self._evidence.add_evidence(
                entity="host",
                value=ip,
                source_plugin="manual",
                observed_confidence=0.93,
                payload={"os_guess": kw.get("os_guess", ""), "alive": True},
            )
            self._emit("host_updated", {"ip": ip})
            return new_host

    # ── Finding management ───────────────────────────────────────────────────

    def add_finding(self, **kw) -> Finding:
        with self._lock:
            # Deduplicate findings based on multiple criteria
            for existing in self.findings:
                # Check for exact match of critical attributes
                if (existing.title == kw.get('title') and 
                    existing.host == kw.get('host') and 
                    existing.port == kw.get('port') and 
                    existing.severity == kw.get('severity')):
                    # Update existing finding with any new information
                    for k, v in kw.items():
                        if v is not None:
                            setattr(existing, k, v)
                    return existing

            # If no matching finding, create a new one
            f = Finding(**kw)
            self.findings.append(f)
            self._evidence.add_evidence(
                entity="finding",
                value=f"{f.host}:{f.port}:{f.title}",
                source_plugin=f.plugin or "manual",
                observed_confidence=0.87,
                related_entities=[f.host] if f.host else [],
                payload={
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "host": f.host,
                    "port": f.port,
                },
            )
            self._emit("finding_added", asdict(f))
            return f

    def top_findings(self, n: int = 10) -> List[Finding]:
        return sorted(self.findings, key=lambda x: x.rank, reverse=True)[:n]

    # ── Directives ───────────────────────────────────────────────────────────

    def add_directive(self, text: str):
        with self._lock:
            self._directives.append(text)
            self._emit("directive", {"text": text})

    def add_chat_message(self, user: str, text: str, ts: str = "") -> Dict[str, Any]:
        msg = {"user": (user or "operator")[:32], "text": (text or "")[:2000], "ts": ts}
        with self._lock:
            self._chat.append(msg)
            self._chat = self._chat[-200:]
        self._emit("chat_message", msg)
        return msg

    def recent_chat(self, n: int = 50) -> List[Dict[str, Any]]:
        return self._chat[-n:]

    def recent_directives(self, n: int = 3) -> List[str]:
        return self._directives[-n:]

    def add_report(self, report: Dict[str, Any]):
        if not isinstance(report, dict):
            return
        with self._lock:
            self._reports.append(report)
            self._reports = self._reports[-30:]
        self._emit("report_stored", {"mission_id": self.mission_id, "reports": len(self._reports)})

    def latest_report(self) -> Dict[str, Any]:
        with self._lock:
            if not self._reports:
                return {}
            return dict(self._reports[-1])

    # ── Ingest results from executor ─────────────────────────────────────────

    def ingest_result(self, result: ActionResult) -> List[Finding]:
        """
        Parse an ActionResult and update hosts/findings accordingly.
        Returns list of new Finding objects added.
        """
        new_findings: List[Finding] = []
        if getattr(result, "quarantined", False) or not getattr(result, "parse_valid", True):
            return new_findings
        parsed  = result.parsed if isinstance(result.parsed, dict) else {}
        target  = parsed.get("_target", result.action.target)
        tool    = result.action.tool

        # Handle the new status/data/error contract
        if isinstance(parsed.get("data"), dict):
            data = parsed.get("data", {})
        else:
            data = {
                key: value
                for key, value in parsed.items()
                if not str(key).startswith("_")
                and key not in {"status", "error", "quarantined", "parse_error"}
            }
        if parsed.get("status") == "error":
            return new_findings

        if tool == "nmap":
            ports    = data.get("ports", [])
            os_guess = data.get("os_guess", "")
            if ports or os_guess:
                h = self.add_host(target, os_guess=os_guess)
                for p in ports:
                    pi = h.add_port(
                        p["port"],
                        service=p.get("service", ""),
                        version=p.get("version", ""),
                        protocol=p.get("protocol", "tcp"),
                    )
                    self._maybe_enrich_port(target, pi)
                    self._evidence.add_evidence(
                        entity="service",
                        value=f"{target}:{p['port']}/{p.get('protocol', 'tcp')}",
                        source_plugin="nmap",
                        observed_confidence=0.91,
                        related_entities=[target],
                        payload={
                            "host": target,
                            "port": p["port"],
                            "protocol": p.get("protocol", "tcp"),
                            "service": p.get("service", ""),
                            "version": p.get("version", ""),
                            "state": p.get("state", "open"),
                        },
                    )
                # Findings for interesting services
                for p in ports:
                    svc = p.get("service", "")
                    ver = p.get("version", "")
                    if svc in ("http", "https"):
                        f = self.add_finding(
                            severity="INFO",
                            title=f"Web service: {svc.upper()} on {target}:{p['port']}",
                            description=f"Server: {ver}",
                            host=target, port=p["port"], plugin="nmap"
                        )
                        new_findings.append(f)
                    elif svc == "ftp":
                        f = self.add_finding(
                            severity="LOW",
                            title=f"FTP service on {target}:{p['port']}",
                            description=f"Version: {ver}. Check for anonymous login.",
                            host=target, port=p["port"], plugin="nmap"
                        )
                        new_findings.append(f)
                    else:
                        # Ensure non-web services show up in reports (e.g. ssh/rdp/smb/db ports).
                        # Severity stays INFO by default; higher-risk classification belongs in policy/intel layers.
                        label = svc.upper() if svc else "UNKNOWN"
                        desc = f"Version: {ver}" if ver else "Service detected via nmap."
                        f = self.add_finding(
                            severity="INFO",
                            title=f"Service: {label} on {target}:{p['port']}",
                            description=desc,
                            host=target,
                            port=p["port"],
                            plugin="nmap",
                        )
                        new_findings.append(f)

        elif tool == "http":
            server  = data.get("server", "")
            status  = data.get("status_code", data.get("status", 0))
            powered = data.get("powered", "")
            if server or status:
                h = self.add_host(target)
                pi = h.add_port(
                    result.action.args.get("port", 80),
                    service="http",
                    version=server,
                )
                self._maybe_enrich_port(target, pi)
                self._evidence.add_evidence(
                    entity="service",
                    value=f"{target}:{result.action.args.get('port', 80)}/tcp",
                    source_plugin="http",
                    observed_confidence=0.84,
                    related_entities=[target],
                    payload={
                        "host": target,
                        "port": result.action.args.get("port", 80),
                        "service": "http",
                        "version": server,
                        "status_code": status,
                        "state": "open",
                    },
                )
                f = self.add_finding(
                    severity="INFO",
                    title=f"HTTP {status} — Server: {server}",
                    description=f"X-Powered-By: {powered}" if powered else f"Status {status}",
                    host=target,
                    port=result.action.args.get("port", 80),
                    plugin="http"
                )
                new_findings.append(f)

        elif tool == "fuzz":
            interesting = data.get("interesting", [])
            for item in interesting:
                self._evidence.add_evidence(
                    entity="finding",
                    value=f"{target}:{result.action.args.get('port', 80)}:{item['path']}",
                    source_plugin="fuzz",
                    observed_confidence=0.76,
                    related_entities=[target],
                    payload={
                        "host": target,
                        "port": result.action.args.get("port", 80),
                        "path": item["path"],
                        "status": item["status"],
                    },
                )
                sev = "MEDIUM" if item["status"] in (200, 403) else "INFO"
                f = self.add_finding(
                    severity=sev,
                    title=f"Web path: {item['path']} [{item['status']}]",
                    description=f"HTTP {item['status']} at {item['path']}",
                    host=target,
                    port=result.action.args.get("port", 80),
                    plugin="fuzz"
                )
                new_findings.append(f)

        return new_findings

    def add_action(self, result: ActionResult):
        with self._lock:
            self.actions.append(result)
        self._emit(
            "action_complete",
            {
                "tool": result.action.tool,
                "target": result.action.target,
                "phase": result.action.phase,
                "success": result.success,
            },
        )

    def _maybe_enrich_port(self, host: str, pi: PortInfo):
        intel = self._intel
        if not intel:
            return
        try:
            info = intel.enrich_offline(version=pi.version)
            cves = info.get("cves") or []
            sources = info.get("sources") or []
            cvss = info.get("cvss")

            if cves:
                pi.cves = list(dict.fromkeys([*pi.cves, *cves]))
                pi.cve_sources = list(dict.fromkeys([*pi.cve_sources, *sources]))
                if pi.cvss is None and isinstance(cvss, (int, float)):
                    pi.cvss = float(cvss)

            intel.enqueue_online(
                version=pi.version,
                host=host,
                port=pi.port,
                protocol=pi.protocol,
            )
        except Exception:
            return

    # ── Summary ──────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            f"=== GRAPH: {len(self.hosts)} hosts | "
            f"{len(self.findings)} findings ==="
        ]
        for ip, h in self.hosts.items():
            ports_str = ", ".join(
                f"{p.port}/{p.service or '?'}" for p in h.ports[:8]
            )
            lines.append(
                f"  HOST {ip:<16}  OS:{h.os_guess or '?':<14}  ports: {ports_str}"
            )
        if self.findings:
            lines.append("\n  TOP FINDINGS:")
            for f in self.top_findings(6):
                lines.append(
                    f"    [{f.severity:<8}] {f.title[:60]} @ {f.host}:{f.port}"
                )
        if self._directives:
            lines.append("\n  DIRECTIVES:")
            for d in self.recent_directives(3):
                lines.append(f"    ▶ {d}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            topology = self._topology_dict()
            return {
                "hosts": {
                    ip: {**asdict(h), "ports": [asdict(p) for p in h.ports]}
                    for ip, h in self.hosts.items()
                },
                "findings": [asdict(f) for f in self.findings],
                "evidence": [asdict(record) for record in self._evidence.active_evidence()],
                "topology": topology,
                "stats": {
                    "hosts":    len(self.hosts),
                    "findings": len(self.findings),
                    "critical": sum(1 for f in self.findings if f.severity == "CRITICAL"),
                    "high":     sum(1 for f in self.findings if f.severity == "HIGH"),
                    "evidence_records": self._evidence.stats()["records"],
                    "contradictions": self._evidence.stats()["contradictions"],
                },
                "latest_report": self.latest_report(),
            }

    def evidence_stats(self) -> Dict[str, Any]:
        return self._evidence.stats()

    def contradictions(self):
        return self._evidence.contradictions_for_mission()

    def prune_expired_evidence(self) -> int:
        removed = self._evidence.prune_expired()
        if removed:
            self._emit("evidence_pruned", {"removed": removed})
        return removed

    def _topology_dict(self) -> Dict[str, Any]:
        # Best-effort subnet bucketing (/24) for visualization.
        sever_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

        def host_severity(ip: str) -> str:
            best = "INFO"
            best_r = 0
            for f in self.findings:
                if f.host != ip:
                    continue
                r = sever_rank.get(f.severity, 0)
                if r > best_r:
                    best_r = r
                    best = f.severity
            return best

        def subnet24(ip: str) -> str:
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return ".".join(parts[:3]) + ".0/24"
            return "unknown"

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes = set()

        for ip, h in self.hosts.items():
            sn = subnet24(ip)
            sn_id = f"subnet:{sn}"
            if sn_id not in seen_nodes:
                seen_nodes.add(sn_id)
                nodes.append({"id": sn_id, "label": sn, "kind": "subnet", "severity": "INFO"})

            host_id = f"host:{ip}"
            if host_id not in seen_nodes:
                seen_nodes.add(host_id)
                nodes.append(
                    {
                        "id": host_id,
                        "label": ip,
                        "kind": "host",
                        "severity": host_severity(ip),
                    }
                )
            edges.append({"from": sn_id, "to": host_id, "kind": "contains"})

            for p in h.ports:
                svc = (p.service or "").lower()
                if svc in ("http", "https", "ssh", "ftp", "mysql", "postgres", "mssql", "smb"):
                    svc_id = f"svc:{ip}:{svc}:{p.port}"
                    if svc_id not in seen_nodes:
                        seen_nodes.add(svc_id)
                        nodes.append(
                            {
                                "id": svc_id,
                                "label": f"{svc}:{p.port}",
                                "kind": "service",
                                "severity": host_severity(ip),
                            }
                        )
                    edges.append({"from": host_id, "to": svc_id, "kind": "exposes"})

        return {"nodes": nodes, "edges": edges}

    # ── Internal ─────────────────────────────────────────────────────────────

    def _emit(self, event: str, data: Any):
        if hasattr(self, "_audit") and self._audit:
            self._audit.log(event, data)
        if self._event_cb:
            try:
                self._event_cb(event, data)
            except Exception:
                pass
