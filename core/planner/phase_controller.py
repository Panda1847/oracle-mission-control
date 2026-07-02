"""Deterministic phase control and action generation."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.correlation import build_attack_candidates, graph_state_summary, rank_attack_paths
from oracle.core.models import Action

from core.orchestrator.job_tracker import JobTracker
from core.planner.fallback_engine import FallbackEngine
from core.planner.retry_engine import RetryEngine
from core.planner.state_machine import MissionPhase, MissionStateMachine, PhaseTransition
from core.planner.transition_rules import PhaseCheckpoint, TransitionRules
from core.policy.policy_engine import PolicyEngine


@dataclass
class PhasePlan:
    """The planner's deterministic view of the next mission step."""

    phase: MissionPhase
    checkpoint: PhaseCheckpoint
    candidates: list[Action] = field(default_factory=list)
    transitions: list[PhaseTransition] = field(default_factory=list)


class PhaseController:
    """Builds deterministic action candidates and phase transitions."""

    WEB_SERVICES = {"http", "https"}

    def __init__(self, policy: PolicyEngine | None = None, state_machine: MissionStateMachine | None = None, registry=None):
        self.policy = policy or PolicyEngine()
        self.state_machine = state_machine or MissionStateMachine()
        self.rules = TransitionRules(self.policy, self.state_machine)
        self.retries = RetryEngine(self.policy)
        self.fallbacks = FallbackEngine(self.policy)
        self.registry = registry

    def describe_phase(self, mission, graph, tracker: JobTracker | None = None) -> str:
        context = self.phase_context(mission, graph, tracker)
        extras = []
        if context["attack_candidates"]:
            extras.append(f"ATTACK CANDIDATES: {len(context['attack_candidates'])}")
        if context["unresolved_findings"]:
            extras.append(f"UNRESOLVED FINDINGS: {len(context['unresolved_findings'])}")
        if context["confidence_gaps"]:
            extras.append(f"CONFIDENCE GAPS: {len(context['confidence_gaps'])}")
        if context["next_exploit_action"]:
            extras.append(
                "NEXT EXPLOIT ACTION: "
                f"{float(context['next_exploit_action'].get('score', 0.0) or 0.0):.2f} "
                f"{' -> '.join(list(context['next_exploit_action'].get('path', []) or [])[:4])}"
            )
        graph_state = context["graph_state"]
        extra_line = ("\n" + "\n".join(extras)) if extras else ""
        return (
            f"PHASE: {context['phase']}\n"
            f"ALLOWED TOOLS: {context['allowed_tools']}\n"
            f"PENDING ACTIONS: {context['pending_actions']}\n"
            f"GRAPH STATE: hosts={graph_state['hosts']} findings={graph_state['findings']} "
            f"evidence={graph_state['evidence_records']} contradictions={graph_state['contradictions']}\n"
            f"CHECKPOINT: {'ready' if context['checkpoint']['ready'] else 'not ready'} "
            f"— {context['checkpoint']['reason']}"
            f"{extra_line}"
        )

    def next_exploit_action(self, graph) -> dict:
        ranked = rank_attack_paths(build_attack_candidates(graph))
        if not ranked:
            return {}
        top = ranked[0]
        return {
            "path": list(top.get("path", []) or []),
            "score": float(top.get("score", 0.0) or 0.0),
            "reason": str(top.get("reason", "ranked by deterministic correlation")),
            "finding_ids": list(top.get("finding_ids", []) or []),
        }

    def phase_context(self, mission, graph, tracker: JobTracker | None = None) -> dict:
        tracker = tracker or JobTracker()
        phase = self.state_machine.normalize(mission.phase)
        candidates = self._build_candidates(phase, mission, graph, tracker)
        checkpoint = self.rules.evaluate(phase, mission, graph, tracker, len(candidates))
        tools = ", ".join(self.policy.allowed_tools(phase.value)) or "none"
        unresolved = self._unresolved_findings(graph)
        confidence_gaps = self._confidence_gaps(graph)
        attack_candidates = rank_attack_paths(build_attack_candidates(graph)) if phase == MissionPhase.EXPLOIT_ANALYSIS else []
        return {
            "phase": phase.value,
            "allowed_tools": tools,
            "pending_actions": len(candidates),
            "graph_state": graph_state_summary(graph),
            "unresolved_findings": [str(getattr(finding, "fid", "") or finding.title) for finding in unresolved],
            "confidence_gaps": confidence_gaps,
            "attack_candidates": attack_candidates[:10],
            "next_exploit_action": self.next_exploit_action(graph) if attack_candidates else {},
            "checkpoint": {
                "ready": bool(checkpoint.ready),
                "reason": checkpoint.reason,
                "metrics": dict(checkpoint.metrics or {}),
            },
        }

    def plan(self, mission, graph, tracker: JobTracker) -> PhasePlan:
        phase = self.state_machine.normalize(mission.phase)
        transitions: list[PhaseTransition] = []

        if phase == MissionPhase.PAUSED and mission.status == "running":
            phase = MissionPhase.DISCOVERY

        while True:
            mission.phase = phase.value
            candidates = self._build_candidates(phase, mission, graph, tracker)
            checkpoint = self.rules.evaluate(phase, mission, graph, tracker, len(candidates))
            if phase in {MissionPhase.EXPLOIT_ANALYSIS, MissionPhase.POST_PROCESS, MissionPhase.REPORTING}:
                return PhasePlan(phase=phase, checkpoint=checkpoint, candidates=[], transitions=transitions)
            if candidates:
                return PhasePlan(phase=phase, checkpoint=checkpoint, candidates=candidates, transitions=transitions)

            next_phase = self.rules.next_phase(phase, checkpoint)
            if next_phase is None:
                if phase in {MissionPhase.DISCOVERY, MissionPhase.ENUMERATION, MissionPhase.VALIDATION}:
                    failed = self.state_machine.transition(phase, MissionPhase.FAILED, f"No actionable candidates remain. {checkpoint.reason}")
                    transitions.append(failed)
                    mission.phase = failed.new.value
                    return PhasePlan(phase=failed.new, checkpoint=PhaseCheckpoint(True, failed.reason), transitions=transitions)
                return PhasePlan(phase=phase, checkpoint=checkpoint, transitions=transitions)

            transition = self.state_machine.transition(phase, next_phase, checkpoint.reason)
            transitions.append(transition)
            phase = transition.new
            if phase in {MissionPhase.COMPLETE, MissionPhase.FAILED}:
                mission.phase = phase.value
                return PhasePlan(phase=phase, checkpoint=PhaseCheckpoint(True, transition.reason), transitions=transitions)

    def _build_candidates(self, phase: MissionPhase, mission, graph, tracker: JobTracker) -> list[Action]:
        if phase == MissionPhase.DISCOVERY:
            return self._discovery_candidates(mission, tracker)
        if phase == MissionPhase.ENUMERATION:
            return self._enumeration_candidates(graph, tracker)
        if phase == MissionPhase.VALIDATION:
            return self._validation_candidates(graph, tracker)
        return []

    def _discovery_candidates(self, mission, tracker: JobTracker) -> list[Action]:
        candidates: list[Action] = []
        tool = self._tool_for_capability("port_scan", "nmap")
        defaults = self.policy.default_args(MissionPhase.DISCOVERY.value, tool)
        timeout = int(defaults.pop("timeout", 60))
        for target in mission.scope:
            base = Action(
                tool=tool,
                target=target,
                args=dict(defaults),
                confidence=self.policy.min_confidence(MissionPhase.DISCOVERY.value),
                reasoning=f"Deterministic discovery scan for in-scope target {target}",
                phase=MissionPhase.DISCOVERY.value,
                timeout=timeout,
                expected="Open services and basic version data",
            )
            candidate = self._with_retry_or_fallback(base, tracker)
            if candidate and not tracker.has_success(base):
                candidates.append(candidate)
        return candidates

    def _enumeration_candidates(self, graph, tracker: JobTracker) -> list[Action]:
        candidates: list[Action] = []
        http_tool = self._tool_for_capability("http_probe", "http")
        fuzz_tool = self._tool_for_capability("web_content_discovery", "fuzz")
        enum_scan_tool = self._tool_for_capability("service_enumeration", "nmap")
        http_defaults = self.policy.default_args(MissionPhase.ENUMERATION.value, http_tool)
        http_timeout = int(http_defaults.pop("timeout", 20))
        fuzz_defaults = self.policy.default_args(MissionPhase.ENUMERATION.value, fuzz_tool)
        fuzz_timeout = int(fuzz_defaults.pop("timeout", 90))
        nmap_defaults = self.policy.default_args(MissionPhase.ENUMERATION.value, enum_scan_tool)
        nmap_timeout = int(nmap_defaults.pop("timeout", 60))

        for host, record in graph.hosts.items():
            for port in record.ports:
                if port.state != "open":
                    continue
                if (port.service or "").lower() in self.WEB_SERVICES:
                    http_action = Action(
                        tool=http_tool,
                        target=host,
                        args={"port": port.port, **http_defaults},
                        confidence=self.policy.min_confidence(MissionPhase.ENUMERATION.value),
                        reasoning=f"Enumerate web service on {host}:{port.port}",
                        phase=MissionPhase.ENUMERATION.value,
                        timeout=http_timeout,
                        expected="HTTP status and response headers",
                    )
                    http_candidate = self._with_retry_or_fallback(http_action, tracker)
                    if http_candidate and not tracker.has_success(http_action):
                        candidates.append(http_candidate)

                    fuzz_action = Action(
                        tool=fuzz_tool,
                        target=host,
                        args={"port": port.port, **fuzz_defaults},
                        confidence=self.policy.min_confidence(MissionPhase.ENUMERATION.value),
                        reasoning=f"Enumerate likely web paths on {host}:{port.port}",
                        phase=MissionPhase.ENUMERATION.value,
                        timeout=fuzz_timeout,
                        expected="Interesting web paths and status codes",
                    )
                    fuzz_candidate = self._with_retry_or_fallback(fuzz_action, tracker)
                    if fuzz_candidate and tracker.has_success(http_action) and not tracker.has_success(fuzz_action):
                        candidates.append(fuzz_candidate)
                elif not port.version:
                    nmap_action = Action(
                        tool=enum_scan_tool,
                        target=host,
                        args={"ports": str(port.port), **nmap_defaults},
                        confidence=self.policy.min_confidence(MissionPhase.ENUMERATION.value),
                        reasoning=f"Confirm service details for {host}:{port.port}",
                        phase=MissionPhase.ENUMERATION.value,
                        timeout=nmap_timeout,
                        expected="More precise service version information",
                    )
                    nmap_candidate = self._with_retry_or_fallback(nmap_action, tracker)
                    if nmap_candidate and not tracker.has_success(nmap_action):
                        candidates.append(nmap_candidate)
        return candidates

    def _validation_candidates(self, graph, tracker: JobTracker) -> list[Action]:
        candidates: list[Action] = []
        validation_tool = self._tool_for_capability("service_validation", "http")
        http_defaults = self.policy.default_args(MissionPhase.VALIDATION.value, validation_tool)
        http_timeout = int(http_defaults.pop("timeout", 25))
        for finding in graph.findings:
            if finding.plugin not in {"http", "fuzz", "nmap"}:
                continue
            if finding.port <= 0:
                continue
            action = Action(
                tool=validation_tool,
                target=finding.host,
                args={"port": finding.port, **http_defaults},
                confidence=self.policy.min_confidence(MissionPhase.VALIDATION.value),
                reasoning=f"Validate finding '{finding.title}' on {finding.host}:{finding.port}",
                phase=MissionPhase.VALIDATION.value,
                timeout=http_timeout,
                expected="Repeatable confirmation of the service/finding",
            )
            candidate = self._with_retry_or_fallback(action, tracker)
            if candidate and not tracker.has_success(action):
                candidates.append(candidate)
        deduped: list[Action] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = JobTracker.signature(candidate)
            if key not in seen:
                seen.add(key)
                deduped.append(candidate)
        return deduped

    def _with_retry_or_fallback(self, action: Action, tracker: JobTracker) -> Action | None:
        if tracker.has_success(action):
            return None
        retry = self.retries.build_retry(action, tracker)
        if retry is not None:
            return retry
        fallback = self.fallbacks.build_fallback(action, tracker)
        if fallback is not None:
            return fallback
        return action

    def _tool_for_capability(self, capability: str, default: str) -> str:
        if self.registry and getattr(self.registry, "plugin_name_for_capability", None):
            selected = self.registry.plugin_name_for_capability(capability)
            if selected:
                return selected
        return default

    @staticmethod
    def _unresolved_findings(graph) -> list:
        unresolved = []
        for finding in list(getattr(graph, "findings", []) or []):
            severity = str(getattr(finding, "severity", "INFO")).upper()
            if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                unresolved.append(finding)
        return unresolved

    @staticmethod
    def _confidence_gaps(graph) -> list[str]:
        gaps: list[str] = []
        for host, record in dict(getattr(graph, "hosts", {}) or {}).items():
            open_ports = [port for port in list(getattr(record, "ports", []) or []) if str(getattr(port, "state", "open")).lower() == "open"]
            if not open_ports:
                gaps.append(f"{host}:no-open-port-evidence")
                continue
            if all(not str(getattr(port, "version", "") or "").strip() for port in open_ports):
                gaps.append(f"{host}:service-version-unknown")
        return gaps
