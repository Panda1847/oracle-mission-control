"""Deterministic mission orchestration with AI as advisor only."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import random
import time
from dataclasses import asdict, replace
from typing import Any, Callable, Iterator, Optional
from uuid import uuid4

from oracle import get_build_identity
from oracle.core.models import Action, ActionResult

from core.attackgraph import attack_graph_summary, build_attack_graph, project_attack_path
from core.ai.advisor import AIAdvisor
from core.ai.council_review import build_council_round
from core.correlation import build_attack_candidates, rank_attack_paths
from core.orchestrator.artifact_router import ArtifactRouter
from core.orchestrator.dispatcher import Dispatcher
from core.orchestrator.event_bus import EventBus
from core.orchestrator.job_tracker import JobTracker
from core.planner.confidence_gate import ConfidenceGate
from core.planner.phase_controller import PhaseController
from core.planner.state_machine import MissionPhase, MissionStateMachine
from core.policy.approval_engine import ApprovalEngine
from core.policy.policy_engine import PolicyEngine
from core.reporting import (
    build_evidence_export,
    build_intelligence_report,
    build_json_export,
    build_mission_summary,
    build_pdf_report,
)
from export.package import build_mission_package
from memory.replay import ReplayStore
from telemetry.health import GLOBAL_HEALTH
from telemetry.metrics import GLOBAL_METRICS
from telemetry.tracing import GLOBAL_TRACES

log = logging.getLogger("oracle.mission_manager")


class MissionManager:
    """Compatibility-preserving deterministic mission engine."""

    MAX_ITERATIONS = 30
    MAX_REPEAT_ATTEMPTS = 3
    VALID_RUNTIME_MODES = {"live", "lab", "test"}

    def __init__(
        self,
        mission,
        graph,
        ai,
        executor,
        safety,
        approve_cb: Optional[Callable] = None,
        audit=None,
        webhook=None,
        opsec: Optional[dict] = None,
        runtime_mode: str | None = None,
    ):
        self.mission = mission
        self.graph = graph
        self.ai = AIAdvisor(ai)
        self.executor = executor
        self.safety = safety
        self.approve_cb = approve_cb
        self.audit = audit
        self.webhook = webhook
        self.opsec = opsec or {}
        self.runtime_mode = str(
            runtime_mode or self.opsec.get("runtime_mode") or os.environ.get("ORACLE_RUNTIME_MODE", "live")
        ).strip().lower()
        if self.runtime_mode not in self.VALID_RUNTIME_MODES:
            raise ValueError(f"Invalid runtime mode '{self.runtime_mode}'. Allowed: {sorted(self.VALID_RUNTIME_MODES)}")

        self.policy = PolicyEngine()
        self.state_machine = MissionStateMachine()
        self.phase_controller = PhaseController(self.policy, self.state_machine, getattr(self.executor, "registry", None))
        self.dispatcher = Dispatcher(self.executor) if hasattr(self.executor, "build_action_result") else None
        self.confidence_gate = ConfidenceGate(self.policy)
        self.approval_engine = ApprovalEngine(self.policy)
        self.event_bus = EventBus()
        graph_storage = getattr(self.graph, "_storage", None)
        storage_base = getattr(graph_storage, "base_dir", None)
        if storage_base:
            tracker_state = Path(storage_base) / f"{self.mission.name}_job_tracker.json"
            replay_base = Path(storage_base) / "replay"
        else:
            tracker_state = Path.home() / ".oracle" / "missions" / f"{self.mission.name}_job_tracker.json"
            replay_base = Path.home() / ".oracle" / "replay"
        self.job_tracker = JobTracker(tracker_state)
        self.replay_store = ReplayStore(replay_base)
        self.artifact_router = ArtifactRouter()
        self.metrics = GLOBAL_METRICS
        self.tracer = GLOBAL_TRACES
        self.health = GLOBAL_HEALTH
        self._resume_phase = self.state_machine.normalize(self.mission.phase)
        self._unavailable_plugins: set[str] = set()
        self._recovery_overrides: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._recovery_budget: dict[tuple[str, str, str], int] = {}
        self._internal_phase_runs: set[str] = set()
        self._state_hash = ""
        self._canonical_reporting: dict[str, Any] | None = None
        self._active_replay_context: dict[str, str] | None = None
        self.mission.phase = self.state_machine.normalize(self.mission.phase).value
        self.health.report("mission_manager", "ok", {"mission": self.mission.name, "runtime_mode": self.runtime_mode})

    def _emit(self, payload: dict, trace_id: str):
        self.event_bus.publish(payload.get("type", "event"), payload, trace_id=trace_id)
        return payload

    def _audit_log(self, event_type: str, payload: dict) -> dict | None:
        if not self.audit:
            return None
        try:
            enriched = dict(payload or {})
            replay = self._active_replay_context or {}
            if replay:
                enriched.setdefault("replay_id", replay.get("replay_id", ""))
                enriched.setdefault("replay_phase", replay.get("phase", ""))
                enriched.setdefault("replay_branch", replay.get("branch", ""))
            return self.audit.log(event_type, enriched)
        except Exception:
            log.exception("Audit logging failed for event=%s", event_type)
            return None

    def _audit_records(self) -> list[dict[str, Any]]:
        if not self.audit or not hasattr(self.audit, "path"):
            return []
        path = Path(getattr(self.audit, "path"))
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                loaded = json.loads(line)
            except Exception:
                continue
            if isinstance(loaded, dict):
                records.append(loaded)
        return records

    def _begin_replay_context(self, *, branch: str, phase: str | None = None) -> dict[str, str]:
        context = {
            "replay_id": uuid4().hex,
            "branch": str(branch or "iteration"),
            "phase": str(phase or self.mission.phase or ""),
            "mission": self.mission.name,
        }
        self._active_replay_context = context
        return context

    def _clear_replay_context(self):
        self._active_replay_context = None

    def _action_key(self, action: Action) -> tuple[str, str, str]:
        return (str(action.phase or ""), str(action.tool or ""), str(action.target or ""))

    def _hash_payload(self, payload: Any) -> str:
        material = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _plugin_inventory(self) -> list[dict]:
        registry = getattr(self.executor, "registry", None)
        if registry is None or not hasattr(registry, "all"):
            return []
        items = []
        for name, plugin in registry.all().items():
            manifest = registry.manifest_for(name) if hasattr(registry, "manifest_for") else None
            health = registry.health(name) if hasattr(registry, "health") else {"healthy": True, "missing_binaries": []}
            if manifest is not None and hasattr(manifest, "__dataclass_fields__"):
                manifest_dict = asdict(manifest)
            else:
                manifest_dict = dict(getattr(manifest, "__dict__", {}))
            items.append(
                {
                    "name": name,
                    "enabled": name not in self._unavailable_plugins,
                    "version": manifest_dict.get("version", ""),
                    "risk_level": manifest_dict.get("risk_level", ""),
                    "binary_present": bool(health.get("healthy", False)),
                    "health_status": "healthy" if health.get("healthy", False) else "degraded",
                    "missing_binaries": list(health.get("missing_binaries", [])),
                    "validator_attached": True,
                    "capabilities": list(manifest_dict.get("capabilities", [])),
                }
            )
        return items

    def _apply_recovery_overrides(self, candidates: list[Action]) -> list[Action]:
        prepared: list[Action] = []
        for candidate in candidates:
            if candidate.tool in self._unavailable_plugins:
                continue
            key = self._action_key(candidate)
            override = self._recovery_overrides.get(key)
            budget = int(self._recovery_budget.get(key, 0))
            if override and budget > 0:
                merged_args = dict(candidate.args or {})
                merged_args.update(dict(override.get("args") or {}))
                timeout = int(override.get("timeout", candidate.timeout) or candidate.timeout)
                reason = str(override.get("reason", "Recovery override applied.")).strip()
                candidate = replace(
                    candidate,
                    args=merged_args,
                    timeout=max(1, timeout),
                    reasoning=f"{candidate.reasoning} {reason}".strip(),
                )
                self._recovery_budget[key] = budget - 1
            prepared.append(candidate)
        return prepared

    def _build_advisor_state(
        self,
        phase: MissionPhase,
        candidates: list[Action],
        checkpoint_reason: str,
        checkpoint_metrics: dict | None,
    ) -> dict:
        recent_actions = []
        failed_actions = []
        for result in list(getattr(self.graph, "actions", []))[-10:]:
            summary = {
                "tool": result.action.tool,
                "target": result.action.target,
                "phase": result.action.phase,
                "success": result.success,
                "error_kind": getattr(result, "error_kind", ""),
                "timeout_hit": getattr(result, "timeout_hit", False),
            }
            recent_actions.append(summary)
            if not result.success:
                failed_actions.append(summary)
        recent_actions = recent_actions[-5:]
        failed_actions = failed_actions[-5:]

        untouched_hosts = [host for host in list(getattr(self.mission, "scope", [])) if host not in getattr(self.graph, "hosts", {})]
        evidence = (self.graph.to_dict() or {}).get("evidence", [])
        clusters = {"high": 0, "medium": 0, "low": 0}
        for record in evidence:
            confidence = float(record.get("confidence", 0.0) or 0.0)
            if confidence >= 0.85:
                clusters["high"] += 1
            elif confidence >= 0.60:
                clusters["medium"] += 1
            else:
                clusters["low"] += 1

        contradictions = len(self.graph.contradictions()) if hasattr(self.graph, "contradictions") else 0
        canonical_attack_graph = self._canonical_attack_graph()
        return {
            "phase": phase.value,
            "checkpoint_reason": checkpoint_reason,
            "phase_completion_metrics": dict(checkpoint_metrics or {}),
            "recent_actions": recent_actions,
            "failed_actions": failed_actions,
            "evidence_confidence_clusters": clusters,
            "contradictions": contradictions,
            "untouched_hosts": untouched_hosts,
            "candidate_count": len(candidates),
            "attack_graph_summary": attack_graph_summary(canonical_attack_graph, top_paths_limit=5),
        }

    def _validate_or_repair_recommendation(self, recommendation: dict | None, candidates: list[Action]) -> tuple[dict | None, dict]:
        if recommendation is None:
            return None, {"status": "missing", "repaired": False, "reason": "Advisor returned no recommendation."}

        rec = dict(recommendation)
        repaired = False
        if (not rec.get("tool") or not rec.get("target")) and isinstance(rec.get("action"), dict):
            action = rec.get("action") or {}
            rec["tool"] = action.get("tool", "")
            rec["target"] = action.get("target", "")
            if "confidence" not in rec and "confidence" in action:
                rec["confidence"] = action.get("confidence")
            repaired = True

        for key in ("reasoning", "expected", "prompt_version"):
            if key in rec and not isinstance(rec.get(key), str):
                rec[key] = str(rec.get(key))
                repaired = True

        try:
            rec["confidence"] = float(rec.get("confidence", 0.0) or 0.0)
        except Exception:
            rec["confidence"] = 0.0
            repaired = True

        tool = str(rec.get("tool", "")).strip()
        target = str(rec.get("target", "")).strip()
        if not tool or not target:
            return None, {"status": "invalid", "repaired": repaired, "reason": "Recommendation missing tool/target."}

        allowed = {(candidate.tool, candidate.target) for candidate in candidates}
        if (tool, target) not in allowed:
            return None, {
                "status": "invalid",
                "repaired": repaired,
                "reason": "Recommendation selected action outside deterministic candidate set.",
            }
        return rec, {"status": "ok", "repaired": repaired, "reason": "Recommendation schema valid."}

    def _schedule_timeout_recovery(self, action: Action):
        lower_args = dict(action.args or {})
        if "threads" in lower_args:
            try:
                lower_args["threads"] = max(1, int(lower_args["threads"]) // 2)
            except Exception:
                lower_args["threads"] = 5
        timing = str(lower_args.get("timing", "T3"))
        lower_args["timing"] = {
            "T5": "T4",
            "T4": "T3",
            "T3": "T2",
            "T2": "T2",
            "T1": "T1",
        }.get(timing, "T2")
        key = self._action_key(action)
        self._recovery_overrides[key] = {
            "args": lower_args,
            "timeout": max(10, int(action.timeout * 0.8)),
            "reason": "Timeout recovery lowered scan intensity for one retry.",
        }
        self._recovery_budget[key] = 1

    def _mark_plugin_unavailable(self, plugin_name: str, reason: str):
        self._unavailable_plugins.add(plugin_name)
        self.graph.add_directive(f"Plugin '{plugin_name}' marked unavailable: {reason}")

    def _mission_snapshot(self, *, phase: str | None = None, status: str | None = None) -> dict[str, Any]:
        return {
            "phase": phase or self.mission.phase,
            "status": status or self.mission.status,
            "iterations": self.mission.iterations,
            "runtime_mode": self.runtime_mode,
            "state_hash": self._state_hash,
            "build_identity": get_build_identity(),
            "plugins": self._plugin_inventory(),
        }

    def _canonical_attack_graph(self) -> dict[str, Any]:
        snapshot = self.graph.to_dict() or {}
        latest_report = dict(snapshot.get("latest_report", {}) or {})
        attack_graph = dict(latest_report.get("attack_graph", {}) or {})
        if not attack_graph:
            attack_graph = build_attack_graph(snapshot)
        return attack_graph

    def _build_reporting_bundle(self, snapshot: dict[str, Any], *, phase: str | None = None, status: str | None = None) -> dict[str, Any]:
        mission_snapshot = self._mission_snapshot(phase=phase, status=status)
        summary = build_mission_summary(self.mission.name, snapshot)
        evidence = build_evidence_export(snapshot)
        intelligence_report = build_intelligence_report(
            self.mission.name,
            snapshot,
            mission_snapshot=mission_snapshot,
        )
        bundle = build_json_export(
            self.mission.name,
            summary,
            evidence,
            intelligence_report=intelligence_report,
            mission_snapshot=mission_snapshot,
        )
        return {
            "snapshot": snapshot,
            "snapshot_hash": self._hash_payload(snapshot),
            "mission_snapshot": mission_snapshot,
            "summary": summary,
            "evidence": evidence,
            "intelligence_report": intelligence_report,
            "bundle": bundle,
        }

    def _graph_snapshot(self) -> dict[str, Any]:
        try:
            snapshot = self.graph.to_dict()
            if isinstance(snapshot, dict):
                return snapshot
        except Exception:
            pass
        return {}

    def _build_replay_payload(
        self,
        *,
        branch: str,
        graph_before: dict[str, Any],
        graph_after: dict[str, Any],
        planner_context: dict[str, Any] | None,
        ai_exchange: dict[str, Any] | None,
        action: Action | None,
        result: ActionResult | None,
        findings: list,
        phase: str | None = None,
    ) -> dict[str, Any]:
        result_payload = asdict(result) if result is not None else {}
        replay_context = self._active_replay_context or {}
        return {
            "replay_id": str(replay_context.get("replay_id", "") or ""),
            "mission": self.mission.name,
            "phase": phase or self.mission.phase,
            "branch": branch,
            "planner_extra": dict(planner_context or {}),
            "ai_prompt": str((ai_exchange or {}).get("prompt", "") or ""),
            "raw_ai_response": (ai_exchange or {}).get("raw_response"),
            "validated_recommendation": (ai_exchange or {}).get("validated_recommendation"),
            "ai_backend": str((ai_exchange or {}).get("backend", "") or ""),
            "ai_source": str((ai_exchange or {}).get("source", "") or ""),
            "action": asdict(action) if action is not None else {},
            "raw_stdout": str(result_payload.get("stdout", "") or "")[:50000],
            "raw_stderr": str(result_payload.get("stderr", "") or "")[:20000],
            "result": result_payload,
            "ingest_delta": [asdict(finding) for finding in findings],
            "graph_snapshot_before": graph_before,
            "graph_snapshot_after": graph_after,
        }

    def _result_is_empty(self, result: ActionResult, new_findings: list) -> bool:
        if new_findings:
            return False
        if result.stdout.strip():
            return False
        parsed = result.parsed or {}
        data = parsed.get("data", parsed if isinstance(parsed, dict) else {})
        if not isinstance(data, dict):
            return True
        for value in data.values():
            if isinstance(value, list) and value:
                return False
            if isinstance(value, dict) and value:
                return False
            if isinstance(value, str) and value.strip():
                return False
            if isinstance(value, (int, float)) and value not in (0, 0.0):
                return False
        return True

    def _consistency_assertions(self) -> list[str]:
        issues: list[str] = []
        snapshot = self.graph.to_dict()
        evidence = snapshot.get("evidence", [])
        topology = snapshot.get("topology", {})
        topology_hosts = [n for n in topology.get("nodes", []) if n.get("kind") == "host"]

        if len(self.graph.findings) > len(evidence):
            issues.append("findings_count_exceeds_evidence_count")
        if len(topology_hosts) != len(self.graph.hosts):
            issues.append("topology_host_count_mismatch")
        if len({f.fid for f in self.graph.findings}) != len(self.graph.findings):
            issues.append("duplicate_finding_ids")
        for finding in self.graph.findings:
            if finding.host and finding.host not in self.graph.hosts:
                issues.append(f"stale_finding_host:{finding.host}")
        registry = getattr(self.executor, "registry", None)
        if registry is not None and hasattr(registry, "all"):
            known = set(registry.all().keys())
            for finding in self.graph.findings:
                if finding.plugin and finding.plugin not in known:
                    issues.append(f"unknown_plugin_provenance:{finding.plugin}")
        return issues

    def _checkpoint_iteration(
        self,
        *,
        action: Action | None,
        result: ActionResult | None,
        findings: list,
        decision_source: str,
        branch: str,
        gate_reason: str = "",
        replay_payload: dict[str, Any] | None = None,
    ) -> dict:
        action_payload = asdict(action) if action else {}
        result_payload = asdict(result) if result else {}
        findings_payload = [asdict(finding) for finding in findings]
        bundle = {
            "mission": {
                "name": self.mission.name,
                "phase": self.mission.phase,
                "status": self.mission.status,
                "iterations": self.mission.iterations,
            },
            "decision": action_payload,
            "decision_source": decision_source,
            "result": result_payload,
            "findings": findings_payload,
            "branch": branch,
            "prev_state_hash": self._state_hash,
        }
        bundle_hash = self._hash_payload(bundle)
        self._state_hash = bundle_hash
        audit_hash = ""
        if self.audit and hasattr(self.audit, "last_hash"):
            audit_hash = str(getattr(self.audit, "last_hash") or "")
        replay_artifact = ""
        if replay_payload:
            replay_record = dict(replay_payload)
            council_source = dict(
                replay_record.get("validated_recommendation", {}) or replay_record.get("raw_ai_response", {}) or {}
            )
            replay_record["state_hash"] = bundle_hash
            replay_record["audit_hash"] = audit_hash
            replay_record["decision_source"] = decision_source
            replay_record["gate_reason"] = gate_reason
            replay_record["branch"] = branch
            replay_record["council_round"] = build_council_round(
                council_source,
                final_action=action_payload,
                decision_source=decision_source,
                gate_reason=gate_reason,
                phase=str(replay_record.get("phase", "") or self.mission.phase),
                branch=branch,
                replay_id=str(replay_record.get("replay_id", "") or ""),
            )
            replay_record["mission_snapshot"] = self._mission_snapshot()
            replay_artifact = str(self.replay_store.create(self.mission.name, replay_record, branch=branch))
            if self._active_replay_context is not None:
                self._active_replay_context["replay_artifact"] = replay_artifact

        if hasattr(self.graph, "transaction_checkpoint"):
            self.graph.transaction_checkpoint(
                mission=self.mission,
                action=action,
                result=result,
                findings=findings,
                audit_hash=audit_hash,
                state_hash=bundle_hash,
                branch=branch,
            )
        else:
            self.graph.save()

        payload = {
            "state_hash": bundle_hash,
            "audit_hash": audit_hash,
            "branch": branch,
            "result_hash": self._hash_payload(result_payload) if result else "",
            "finding_hash": self._hash_payload(findings_payload),
            "replay_artifact": replay_artifact,
        }
        self._audit_log(
            "iteration_checkpoint",
            {
                **payload,
                "decision_hash": self._hash_payload(action_payload),
                "mission": {
                    "name": self.mission.name,
                    "phase": self.mission.phase,
                    "status": self.mission.status,
                    "iterations": self.mission.iterations,
                },
                "replay_artifact": replay_artifact,
            },
        )
        self._clear_replay_context()
        return payload

    def _sleep_between_actions(self):
        base = 0.5
        jitter = self.opsec.get("action_jitter")
        network_throttle = bool(self.opsec.get("network_throttle", False))
        if self.mission.profile == "stealth":
            network_throttle = True
        if jitter and isinstance(jitter, (list, tuple)) and len(jitter) == 2:
            try:
                low = float(jitter[0])
                high = float(jitter[1])
                if high < low:
                    low, high = high, low
                time.sleep(random.uniform(max(0.0, low), max(0.0, high)))
                return
            except Exception:
                pass
        if network_throttle:
            time.sleep(base)
            return
        time.sleep(0.2)

    def _force_phase_shift_if_repeated(self, action: Action, trace_id: str) -> dict | None:
        stats = self.job_tracker.stats_for(action)
        if stats.attempts < self.MAX_REPEAT_ATTEMPTS or stats.successes > 0:
            return None
        current = self.state_machine.normalize(self.mission.phase)
        nxt = self.state_machine.next_linear_phase(current)
        if nxt is None or not self.state_machine.can_transition(current, nxt):
            return None
        self.mission.phase = nxt.value
        payload = {
            "type": "phase_shift_forced",
            "from": current.value,
            "to": nxt.value,
            "reason": f"Repeated action threshold reached for {action.tool} on {action.target}",
        }
        self._emit(payload, trace_id)
        self._audit_log("phase_shift_forced", payload)
        return payload

    def _handle_internal_phase(self, phase: MissionPhase) -> dict:
        phase_key = phase.value
        if phase_key in self._internal_phase_runs:
            return {"type": "phase_internal", "phase": phase_key, "status": "already_complete"}

        phase_events: list[dict] = []
        if phase == MissionPhase.EXPLOIT_ANALYSIS:
            candidates = rank_attack_paths(build_attack_candidates(self.graph))
            generated = 0
            for candidate in candidates[:20]:
                path = list(candidate.get("path", []) or [])
                if not path:
                    continue
                anchor = str(path[-1])
                host = ""
                port = 0
                parts = anchor.split(":")
                if len(parts) >= 3:
                    host = parts[0]
                    try:
                        port = int(parts[-1])
                    except Exception:
                        port = 0
                score = float(candidate.get("score", 0.0) or 0.0)
                severity = "HIGH" if score >= 0.82 else "MEDIUM" if score >= 0.62 else "LOW"
                reason = str(candidate.get("reason", "correlated exploit path"))
                path_text = " -> ".join(path[:6])
                finding = self.graph.add_finding(
                    severity=severity,
                    title=f"Exploit path candidate ({score:.2f})",
                    description=f"{reason}; path={path_text}",
                    host=host,
                    port=port,
                    plugin="correlation",
                )
                if finding:
                    generated += 1
                path_projection = project_attack_path(self.graph.to_dict() or {}, path)
                phase_events.append(
                    {
                        "type": "attack_path_generated",
                        "score": score,
                        "path": path,
                        "path_id": path_projection["path_id"],
                        "node_ids": path_projection["node_ids"],
                        "reason": reason,
                        "finding_ids": list(candidate.get("finding_ids", []) or []),
                    }
                )
            attack_graph = self._canonical_attack_graph()
            payload = {
                "type": "phase_internal",
                "phase": phase_key,
                "status": "complete",
                "correlated_services": len(candidates),
                "generated_findings": generated,
                "attack_paths": candidates[:10],
                "attack_graph_summary": attack_graph_summary(attack_graph, top_paths_limit=5),
                "events": phase_events[:20],
            }
        elif phase == MissionPhase.POST_PROCESS:
            pruned = self.graph.prune_expired_evidence() if hasattr(self.graph, "prune_expired_evidence") else 0
            contradictions = len(self.graph.contradictions()) if hasattr(self.graph, "contradictions") else 0
            self.graph.save()
            payload = {
                "type": "phase_internal",
                "phase": phase_key,
                "status": "complete",
                "pruned_evidence": int(pruned),
                "contradictions": contradictions,
            }
        elif phase == MissionPhase.REPORTING:
            snapshot = self.graph.to_dict()
            report_bundle = self._build_reporting_bundle(snapshot, phase=phase_key, status=self.mission.status)
            summary = report_bundle["summary"]
            evidence = report_bundle["evidence"]
            intelligence_report = report_bundle["intelligence_report"]
            if hasattr(self.graph, "add_report"):
                self.graph.add_report(intelligence_report)
                self.graph.save()
            self._canonical_reporting = report_bundle
            bundle = report_bundle["bundle"]
            summary_art = self.artifact_router.route("reports", f"{self.mission.name}_interim_summary", summary, extension=".json")
            evidence_art = self.artifact_router.route("reports", f"{self.mission.name}_interim_evidence", evidence, extension=".json")
            intel_art = self.artifact_router.route("reports", f"{self.mission.name}_interim_intelligence", intelligence_report, extension=".json")
            bundle_art = self.artifact_router.route("reports", f"{self.mission.name}_interim_bundle", bundle, extension=".json")
            phase_events.extend(
                [
                    {"type": "report_generated", "artifact": summary_art.path, "kind": "summary_json"},
                    {"type": "report_generated", "artifact": evidence_art.path, "kind": "evidence_json"},
                    {"type": "report_generated", "artifact": intel_art.path, "kind": "intelligence_json"},
                    {"type": "report_generated", "artifact": bundle_art.path, "kind": "bundle_json"},
                ]
            )
            payload = {
                "type": "phase_internal",
                "phase": phase_key,
                "status": "complete",
                "artifacts": [summary_art.path, evidence_art.path, intel_art.path, bundle_art.path],
                "events": phase_events,
            }
        else:
            payload = {"type": "phase_internal", "phase": phase_key, "status": "skipped"}

        self._internal_phase_runs.add(phase_key)
        return payload

    def run(self) -> Iterator[dict]:
        with self.tracer.span("mission.run", mission=self.mission.name) as trace_id:
            self.metrics.inc("mission_runs_total")
            start_payload = {
                "type": "start",
                "mission": self.mission.name,
                "scope": self.mission.scope,
                "runtime_mode": self.runtime_mode,
                "build_identity": get_build_identity(),
                "plugins": self._plugin_inventory(),
            }
            yield self._emit(start_payload, trace_id)
            self._audit_log("mission_start", start_payload)

            if self.runtime_mode == "live" and "simulated" in str(getattr(self.mission, "objective", "")).lower():
                warn = {
                    "type": "integrity_warning",
                    "reason": "Live runtime started with a simulated objective string.",
                    "objective": getattr(self.mission, "objective", ""),
                }
                self.health.report("mission_manager", "degraded", {"reason": warn["reason"]})
                yield self._emit(warn, trace_id)
                self._audit_log("integrity_warning", warn)

            was_paused = False
            max_iterations = min(getattr(self.mission, "max_iterations", self.MAX_ITERATIONS), self.MAX_ITERATIONS)

            while self.mission.iterations < max_iterations and self.mission.status not in ("stopped", "complete"):
                if self.mission.status == "paused":
                    if not was_paused:
                        self._resume_phase = self.state_machine.normalize(self.mission.phase)
                        self.mission.phase = MissionPhase.PAUSED.value
                        payload = {"type": "paused"}
                        yield self._emit(payload, trace_id)
                        self._audit_log("paused", {"mission": self.mission.name})
                        was_paused = True
                    time.sleep(0.2)
                    continue

                if was_paused:
                    self.mission.phase = self._resume_phase.value
                    was_paused = False

                if self.mission.status != "running":
                    reason = f"status={self.mission.status}"
                    self.mission.status = "stopped"
                    self.health.report("mission_manager", "degraded", {"reason": reason})
                    yield self._emit({"type": "stopped", "reason": reason}, trace_id)
                    self._audit_log("mission_stopped", {"reason": reason})
                    break

                self.mission.iterations += 1
                self.metrics.set_gauge("mission_iteration", self.mission.iterations)
                yield self._emit({"type": "thinking", "iteration": self.mission.iterations}, trace_id)

                plan = self.phase_controller.plan(self.mission, self.graph, self.job_tracker)
                for transition in plan.transitions:
                    self.mission.phase = transition.new.value
                    payload = {
                        "type": "phase_up",
                        "phase": transition.new.value,
                        "from": transition.old.value,
                        "reason": transition.reason,
                    }
                    yield self._emit(payload, trace_id)
                    self._audit_log("phase_up", payload)

                if plan.phase == MissionPhase.COMPLETE:
                    self.mission.phase = MissionPhase.COMPLETE.value
                    break

                if plan.phase == MissionPhase.FAILED:
                    self.mission.phase = MissionPhase.FAILED.value
                    self.mission.status = "stopped"
                    self.health.report("mission_manager", "degraded", {"phase": "FAILED", "reason": plan.checkpoint.reason})
                    yield self._emit({"type": "stopped", "reason": plan.checkpoint.reason}, trace_id)
                    self._audit_log("mission_failed", {"reason": plan.checkpoint.reason})
                    break

                if plan.phase in {MissionPhase.EXPLOIT_ANALYSIS, MissionPhase.POST_PROCESS, MissionPhase.REPORTING}:
                    graph_before = self._graph_snapshot()
                    planner_context = self.phase_controller.phase_context(self.mission, self.graph, self.job_tracker)
                    self._begin_replay_context(branch=f"{plan.phase.value.lower()}_internal", phase=plan.phase.value)
                    internal_payload = self._handle_internal_phase(plan.phase)
                    for event in list(internal_payload.pop("events", []) or []):
                        yield self._emit(event, trace_id)
                        self._audit_log(event.get("type", "phase_internal_event"), event)
                    yield self._emit(internal_payload, trace_id)
                    self._audit_log("phase_internal", internal_payload)
                    graph_after = self._graph_snapshot()
                    next_phase = self.state_machine.next_linear_phase(plan.phase)
                    if next_phase is not None:
                        old = plan.phase
                        self.mission.phase = next_phase.value
                        phase_payload = {
                            "type": "phase_up",
                            "phase": next_phase.value,
                            "from": old.value,
                            "reason": f"Internal phase handler completed: {internal_payload.get('status', 'complete')}",
                        }
                        yield self._emit(phase_payload, trace_id)
                        self._audit_log("phase_up", phase_payload)
                    checkpoint = self._checkpoint_iteration(
                        action=None,
                        result=None,
                        findings=[],
                        decision_source="deterministic_internal",
                        gate_reason="Internal phase completed without advisor arbitration.",
                        branch=f"{plan.phase.value.lower()}_internal",
                        replay_payload=self._build_replay_payload(
                            branch=f"{plan.phase.value.lower()}_internal",
                            graph_before=graph_before,
                            graph_after=graph_after,
                            planner_context=planner_context,
                            ai_exchange={},
                            action=None,
                            result=None,
                            findings=[],
                            phase=plan.phase.value,
                        ),
                    )
                    yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                    continue

                candidates = self._apply_recovery_overrides(list(plan.candidates))
                if not candidates:
                    reason = "No executable candidates available after availability/recovery filtering."
                    self.mission.phase = MissionPhase.FAILED.value
                    self.mission.status = "stopped"
                    self.health.report("mission_manager", "degraded", {"reason": reason})
                    payload = {"type": "stopped", "reason": reason}
                    yield self._emit(payload, trace_id)
                    self._audit_log("mission_failed", payload)
                    break

                graph_before = self._graph_snapshot()
                planner_context = self.phase_controller.phase_context(self.mission, self.graph, self.job_tracker)
                self._begin_replay_context(branch=plan.phase.value.lower(), phase=plan.phase.value)
                advisor_state = self._build_advisor_state(plan.phase, candidates, plan.checkpoint.reason, plan.checkpoint.metrics)
                yield self._emit(
                    {
                        "type": "ai_decision_start",
                        "phase": plan.phase.value,
                        "candidate_count": len(candidates),
                        "attack_graph_summary": dict(advisor_state.get("attack_graph_summary", {}) or {}),
                    },
                    trace_id,
                )

                recommendation = self.ai.recommend(
                    self.mission,
                    self.graph,
                    plan.phase.value,
                    candidates,
                    plan.checkpoint.reason,
                    advisor_state=advisor_state,
                )
                yield self._emit(
                    {
                        "type": "ai_decision_result",
                        "has_recommendation": recommendation is not None,
                        "recommended_tool": (recommendation or {}).get("tool", ""),
                        "recommended_target": (recommendation or {}).get("target", ""),
                        "recommendation_confidence": float((recommendation or {}).get("confidence", 0.0) or 0.0),
                        "recommendation_reasoning": str((recommendation or {}).get("reasoning", "") or ""),
                        "backend": str((self.ai.last_exchange or {}).get("backend", "") or ""),
                        "council_arbiter": str(((recommendation or {}).get("council", {}) or {}).get("arbiter", "") or ""),
                        "council": dict((recommendation or {}).get("council", {}) or {}),
                    },
                    trace_id,
                )

                recommendation, schema_state = self._validate_or_repair_recommendation(recommendation, candidates)
                yield self._emit({"type": "schema_validation", **schema_state}, trace_id)
                if recommendation is None and schema_state["status"] == "invalid":
                    yield self._emit({"type": "schema_repair_retry", "reason": schema_state["reason"]}, trace_id)
                    retry_recommendation = self.ai.recommend(
                        self.mission,
                        self.graph,
                        plan.phase.value,
                        candidates,
                        f"{plan.checkpoint.reason} (schema repair retry)",
                        advisor_state=advisor_state,
                    )
                    recommendation, schema_state = self._validate_or_repair_recommendation(retry_recommendation, candidates)
                    yield self._emit({"type": "schema_validation", **schema_state, "retry": True}, trace_id)

                gate = self.confidence_gate.select(plan.phase.value, candidates, recommendation)
                action = gate.action
                action.phase = plan.phase.value
                action.requires_approval = bool(self.opsec.get("copilot_mode")) or self.approval_engine.requires_approval(action, gate.confidence)
                self.metrics.observe("planner_gate_confidence", action.confidence, labels={"phase": action.phase})

                decision_payload = {
                    "type": "decision",
                    "action": action,
                    "thinking": plan.checkpoint.reason,
                    "reasoning": action.reasoning,
                    "confidence": action.confidence,
                    "decision_source": gate.source,
                    "gate_reason": gate.reason,
                    "council": dict((recommendation or {}).get("council", {}) or {}),
                }
                yield self._emit(decision_payload, trace_id)
                self._audit_log(
                    "decision",
                    {
                        "tool": action.tool,
                        "target": action.target,
                        "args": action.args,
                        "phase": action.phase,
                        "confidence": action.confidence,
                        "source": gate.source,
                        "gate_reason": gate.reason,
                        "advisor_state": advisor_state,
                        "council": dict((recommendation or {}).get("council", {}) or {}),
                    },
                )

                forced_shift = self._force_phase_shift_if_repeated(action, trace_id)
                if forced_shift is not None:
                    checkpoint = self._checkpoint_iteration(
                        action=action,
                        result=None,
                        findings=[],
                        decision_source=gate.source,
                        gate_reason=gate.reason,
                        branch="repeated_action_phase_shift",
                        replay_payload=self._build_replay_payload(
                            branch="repeated_action_phase_shift",
                            graph_before=graph_before,
                            graph_after=self._graph_snapshot(),
                            planner_context=planner_context,
                            ai_exchange=dict(self.ai.last_exchange or {}),
                            action=action,
                            result=None,
                            findings=[],
                        ),
                    )
                    yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                    continue

                if action.requires_approval:
                    yield self._emit({"type": "approval_required", "tool": action.tool, "target": action.target, "phase": action.phase}, trace_id)
                    if self.webhook:
                        self.webhook.notify("approval_required", {"tool": action.tool, "target": action.target, "phase": action.phase})
                    if not self.approve_cb:
                        self.job_tracker.record_block(action, "approval callback missing")
                        payload = {"type": "approval_blocked", "reason": "Approval callback is not configured.", "tool": action.tool}
                        yield self._emit(payload, trace_id)
                        self._audit_log("approval_blocked", payload)
                        checkpoint = self._checkpoint_iteration(
                            action=action,
                            result=None,
                            findings=[],
                            decision_source=gate.source,
                            gate_reason=gate.reason,
                            branch="approval_blocked",
                            replay_payload=self._build_replay_payload(
                                branch="approval_blocked",
                                graph_before=graph_before,
                                graph_after=self._graph_snapshot(),
                                planner_context=planner_context,
                                ai_exchange=dict(self.ai.last_exchange or {}),
                                action=action,
                                result=None,
                                findings=[],
                            ),
                        )
                        yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                        continue
                    approved = self.approve_cb(action)
                    if not approved:
                        self.graph.add_directive(f"Operator denied: {action.tool} on {action.target}")
                        payload = {"type": "denied", "tool": action.tool, "target": action.target}
                        yield self._emit(payload, trace_id)
                        self._audit_log("approval_denied", payload)
                        checkpoint = self._checkpoint_iteration(
                            action=action,
                            result=None,
                            findings=[],
                            decision_source=gate.source,
                            gate_reason=gate.reason,
                            branch="approval_denied",
                            replay_payload=self._build_replay_payload(
                                branch="approval_denied",
                                graph_before=graph_before,
                                graph_after=self._graph_snapshot(),
                                planner_context=planner_context,
                                ai_exchange=dict(self.ai.last_exchange or {}),
                                action=action,
                                result=None,
                                findings=[],
                            ),
                        )
                        yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                        continue
                    yield self._emit({"type": "approval_ok", "tool": action.tool, "target": action.target}, trace_id)
                else:
                    yield self._emit({"type": "approval_ok", "tool": action.tool, "target": action.target, "auto": True}, trace_id)

                cmd = self.executor.build_command(action)
                allowed, reason = self.safety.validate(action, cmd)
                if not allowed:
                    self.job_tracker.record_block(action, reason)
                    self.metrics.inc("mission_safety_blocks_total", labels={"tool": action.tool})
                    payload = {"type": "safety_block", "reason": reason, "cmd": cmd}
                    yield self._emit(payload, trace_id)
                    self._audit_log("safety_block", {"tool": action.tool, "target": action.target, "cmd": cmd, "reason": reason})
                    checkpoint = self._checkpoint_iteration(
                        action=action,
                        result=None,
                        findings=[],
                        decision_source=gate.source,
                        gate_reason=gate.reason,
                        branch="safety_blocked",
                        replay_payload=self._build_replay_payload(
                            branch="safety_blocked",
                            graph_before=graph_before,
                            graph_after=self._graph_snapshot(),
                            planner_context=planner_context,
                            ai_exchange=dict(self.ai.last_exchange or {}),
                            action=action,
                            result=None,
                            findings=[],
                        ),
                    )
                    yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                    continue

                yield self._emit({"type": "safety_ok", "tool": action.tool, "target": action.target, "cmd": cmd}, trace_id)
                yield self._emit({"type": "executing", "tool": action.tool, "target": action.target, "timeout": action.timeout}, trace_id)

                start = time.time()
                try:
                    result = self.dispatcher.dispatch(action, cmd) if self.dispatcher else self.executor.run(action)
                except Exception as exc:
                    result = ActionResult(
                        action=action,
                        stdout="",
                        stderr=str(exc),
                        returncode=-1,
                        duration=max(0.0, time.time() - start),
                        parsed={"status": "error", "data": {}, "error": f"execution_exception:{exc}"},
                        parse_valid=False,
                        quarantined=True,
                        error_kind="execution_exception",
                    )
                self.metrics.observe("plugin_runtime_seconds", max(0.0, time.time() - start), labels={"tool": action.tool})
                self.job_tracker.record_result(result)
                self.graph.add_action(result)

                yield self._emit(
                    {
                        "type": "execution_result",
                        "tool": action.tool,
                        "target": action.target,
                        "returncode": result.returncode,
                        "duration": result.duration,
                        "timeout_hit": result.timeout_hit,
                        "binary_missing": result.binary_missing,
                        "error_kind": result.error_kind,
                        "stdout_bytes": len(result.stdout or ""),
                        "stderr_bytes": len(result.stderr or ""),
                    },
                    trace_id,
                )
                self._audit_log(
                    "result",
                    {
                        "tool": action.tool,
                        "target": action.target,
                        "cmd": (result.parsed or {}).get("_cmd", cmd),
                        "returncode": result.returncode,
                        "duration": result.duration,
                        "timeout_hit": bool(result.timeout_hit),
                        "binary_missing": bool(result.binary_missing),
                        "error_kind": result.error_kind,
                    },
                )

                if result.timeout_hit:
                    self._schedule_timeout_recovery(action)
                    yield self._emit(
                        {
                            "type": "recovery_policy_applied",
                            "failure_type": "timeout",
                            "response": "retry once lower intensity",
                            "tool": action.tool,
                            "target": action.target,
                        },
                        trace_id,
                    )

                if result.binary_missing or result.error_kind in {"binary_missing", "plugin_unavailable"}:
                    self._mark_plugin_unavailable(action.tool, result.stderr or result.error_kind or "missing")
                    payload = {
                        "type": "plugin_unavailable",
                        "tool": action.tool,
                        "reason": result.stderr or result.error_kind or "unavailable",
                    }
                    yield self._emit(payload, trace_id)
                    self._audit_log("plugin_unavailable", payload)
                    checkpoint = self._checkpoint_iteration(
                        action=action,
                        result=result,
                        findings=[],
                        decision_source=gate.source,
                        gate_reason=gate.reason,
                        branch="plugin_unavailable",
                        replay_payload=self._build_replay_payload(
                            branch="plugin_unavailable",
                            graph_before=graph_before,
                            graph_after=self._graph_snapshot(),
                            planner_context=planner_context,
                            ai_exchange=dict(self.ai.last_exchange or {}),
                            action=action,
                            result=result,
                            findings=[],
                        ),
                    )
                    yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                    continue

                parsed = result.parsed or {}
                if result.quarantined or (not result.parse_valid) or parsed.get("status") == "error":
                    payload = {
                        "type": "parse_quarantined",
                        "tool": action.tool,
                        "target": action.target,
                        "reason": parsed.get("error") or result.error_kind or "parse contract validation failed",
                    }
                    yield self._emit(payload, trace_id)
                    self._audit_log("parse_quarantined", payload)
                    checkpoint = self._checkpoint_iteration(
                        action=action,
                        result=result,
                        findings=[],
                        decision_source=gate.source,
                        gate_reason=gate.reason,
                        branch="parse_quarantined",
                        replay_payload=self._build_replay_payload(
                            branch="parse_quarantined",
                            graph_before=graph_before,
                            graph_after=self._graph_snapshot(),
                            planner_context=planner_context,
                            ai_exchange=dict(self.ai.last_exchange or {}),
                            action=action,
                            result=result,
                            findings=[],
                        ),
                    )
                    yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                    continue

                yield self._emit({"type": "parse_ok", "tool": action.tool, "target": action.target}, trace_id)
                new_findings = self.graph.ingest_result(result)
                attack_graph = self._canonical_attack_graph()
                attack_graph_nodes = list(attack_graph.get("nodes", []) or [])
                yield self._emit(
                    {
                        "type": "graph_ingest",
                        "tool": action.tool,
                        "target": action.target,
                        "findings": len(new_findings),
                        "hosts": len(self.graph.hosts),
                        "attack_graph_summary": attack_graph_summary(attack_graph, top_paths_limit=3),
                        "focus_node_ids": [str(node.get("id", "") or "") for node in attack_graph_nodes[:5] if str(node.get("id", "") or "")],
                    },
                    trace_id,
                )

                if self._result_is_empty(result, new_findings):
                    self.job_tracker.record_error(action, "empty_result")
                    payload = {
                        "type": "recovery_policy_applied",
                        "failure_type": "empty_result",
                        "response": "choose alternate tool",
                        "tool": action.tool,
                        "target": action.target,
                    }
                    yield self._emit(payload, trace_id)
                    self._audit_log("recovery_empty_result", payload)

                for finding in new_findings:
                    yield self._emit({"type": "finding", "finding": finding}, trace_id)
                    self._audit_log(
                        "finding",
                        {
                            "severity": finding.severity,
                            "title": finding.title,
                            "host": finding.host,
                            "port": finding.port,
                            "plugin": finding.plugin,
                        },
                    )

                pruned_evidence = self.graph.prune_expired_evidence() if hasattr(self.graph, "prune_expired_evidence") else 0
                if pruned_evidence:
                    yield self._emit({"type": "evidence_pruned", "removed": int(pruned_evidence)}, trace_id)
                    self._audit_log("evidence_pruned", {"removed": int(pruned_evidence)})

                strategy_reflection = {
                    "type": "strategy_reflection",
                    "tool": action.tool,
                    "target": action.target,
                    "success": result.success,
                    "new_findings": len(new_findings),
                    "timeout_hit": result.timeout_hit,
                    "phase": action.phase,
                    "advisor_cluster": advisor_state.get("evidence_confidence_clusters", {}),
                }
                yield self._emit(strategy_reflection, trace_id)
                self._audit_log("strategy_reflection", strategy_reflection)

                feedback_payload = {
                    "type": "next_iteration_feedback",
                    "phase": self.mission.phase,
                    "tool": action.tool,
                    "target": action.target,
                    "next_candidates_expected": len(candidates),
                    "failed_actions_recent": len(advisor_state.get("failed_actions", [])),
                    "untouched_hosts": advisor_state.get("untouched_hosts", []),
                }
                yield self._emit(feedback_payload, trace_id)
                self._audit_log("next_iteration_feedback", feedback_payload)

                consistency_issues = self._consistency_assertions()
                if consistency_issues:
                    payload = {"type": "integrity_warning", "issues": consistency_issues}
                    self.health.report("mission_manager", "degraded", {"issues": consistency_issues})
                    yield self._emit(payload, trace_id)
                    self._audit_log("integrity_warning", payload)
                else:
                    yield self._emit({"type": "consistency_ok"}, trace_id)

                yield self._emit({"type": "result", "result": result, "findings": len(new_findings)}, trace_id)
                checkpoint = self._checkpoint_iteration(
                    action=action,
                    result=result,
                    findings=new_findings,
                    decision_source=gate.source,
                    gate_reason=gate.reason,
                    branch="normal",
                    replay_payload=self._build_replay_payload(
                        branch="normal",
                        graph_before=graph_before,
                        graph_after=self._graph_snapshot(),
                        planner_context=planner_context,
                        ai_exchange=dict(self.ai.last_exchange or {}),
                        action=action,
                        result=result,
                        findings=new_findings,
                    ),
                )
                yield self._emit({"type": "checkpoint", **checkpoint}, trace_id)
                self.graph.save()
                self._sleep_between_actions()

            if self.mission.status == "running":
                self.mission.status = "complete"
                self.mission.phase = MissionPhase.COMPLETE.value

            self.graph.save()
            snapshot = self.graph.to_dict()
            self.artifact_router.route("mission", self.mission.name, snapshot, extension=".json")
            report_bundle = self._canonical_reporting or self._build_reporting_bundle(snapshot)
            if self._canonical_reporting is None and hasattr(self.graph, "add_report"):
                self.graph.add_report(report_bundle["intelligence_report"])
                self.graph.save()
            summary_art = self.artifact_router.route("reports", f"{self.mission.name}_summary", report_bundle["summary"], extension=".json")
            evidence_art = self.artifact_router.route("reports", f"{self.mission.name}_evidence", report_bundle["evidence"], extension=".json")
            intel_art = self.artifact_router.route("reports", f"{self.mission.name}_intelligence", report_bundle["intelligence_report"], extension=".json")
            bundle_art = self.artifact_router.route("reports", f"{self.mission.name}_bundle", report_bundle["bundle"], extension=".json")
            pdf_bytes = build_pdf_report(report_bundle["summary"])
            pdf_art = self.artifact_router.route(
                "reports",
                f"{self.mission.name}_summary",
                pdf_bytes,
                extension=".pdf",
                content_type="application/pdf",
            )
            package = build_mission_package(
                self.mission.name,
                mission_snapshot=report_bundle["mission_snapshot"],
                graph_snapshot=snapshot,
                summary=report_bundle["summary"],
                evidence=report_bundle["evidence"],
                intelligence_report=report_bundle["intelligence_report"],
                bundle=report_bundle["bundle"],
                pdf_report=pdf_bytes,
                replay_artifacts=self.replay_store.list(self.mission.name),
                provenance_records=self._audit_records(),
            )
            package_art = self.artifact_router.route(
                "packages",
                f"{self.mission.name}_package",
                package.payload,
                extension=".zip",
                content_type="application/zip",
            )
            for artifact, kind in (
                (summary_art.path, "summary_json"),
                (evidence_art.path, "evidence_json"),
                (intel_art.path, "intelligence_json"),
                (bundle_art.path, "bundle_json"),
                (pdf_art.path, "summary_pdf"),
                (package_art.path, "mission_package_zip"),
            ):
                yield self._emit({"type": "report_generated", "artifact": artifact, "kind": kind, "final": True}, trace_id)
            if self.mission.status == "complete":
                self.health.report("mission_manager", "ok", {"mission": self.mission.name, "status": "complete"})
                payload = {
                    "type": "complete",
                    "iterations": self.mission.iterations,
                    "hosts": len(self.graph.hosts),
                    "findings": len(self.graph.findings),
                    "state_hash": self._state_hash,
                }
                yield self._emit(payload, trace_id)
                self._audit_log(
                    "mission_complete",
                    {
                        "iterations": self.mission.iterations,
                        "hosts": len(self.graph.hosts),
                        "findings": len(self.graph.findings),
                        "state_hash": self._state_hash,
                    },
                )
