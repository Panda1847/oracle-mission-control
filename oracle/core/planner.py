"""Compatibility facade for the enterprise phase controller."""

from __future__ import annotations

from core.orchestrator.job_tracker import JobTracker
from core.planner.phase_controller import PhaseController


class Planner:
    """Keeps the old planner import path working while using the new planner."""

    def __init__(self, tracker: JobTracker | None = None):
        self.controller = PhaseController()
        self.tracker = tracker or JobTracker()

    @staticmethod
    def _unresolved_findings(graph) -> list:
        findings = list(getattr(graph, "findings", []) or [])
        resolved = {"INFO"}
        return [finding for finding in findings if str(getattr(finding, "severity", "INFO")).upper() not in resolved]

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
            if not any((str(getattr(port, "service", "") or "").lower() in {"http", "https"}) for port in open_ports):
                gaps.append(f"{host}:no-web-surface-enumerated")
        return gaps

    def next_exploit_action(self, graph) -> dict:
        return self.controller.next_exploit_action(graph)

    def evaluate(self, mission, graph) -> str:
        context = self.controller.phase_context(mission, graph, self.tracker)
        description = self.controller.describe_phase(mission, graph, self.tracker)
        unresolved = self._unresolved_findings(graph)
        gaps = self._confidence_gaps(graph)
        lines = [
            description,
            f"UNRESOLVED FINDINGS: {len(unresolved)}",
            f"CONFIDENCE GAPS: {len(gaps)}",
        ]
        graph_state = context.get("graph_state", {})
        lines.append(
            "GRAPH STATE: "
            f"hosts={graph_state.get('hosts', 0)} "
            f"findings={graph_state.get('findings', 0)} "
            f"evidence={graph_state.get('evidence_records', 0)} "
            f"contradictions={graph_state.get('contradictions', 0)}"
        )
        if str(getattr(mission, "phase", "")).upper() == "EXPLOIT_ANALYSIS":
            ranked = list(context.get("attack_candidates", []) or [])
            if ranked:
                preview = "\n".join(
                    f"- {entry.get('score', 0.0):.2f}: {' -> '.join(entry.get('path', [])[:4])}"
                    for entry in ranked[:3]
                )
                lines.append("TOP ATTACK PATHS:")
                lines.append(preview)
                next_action = self.next_exploit_action(graph)
                if next_action:
                    lines.append(
                        f"NEXT_EXPLOIT_ACTION: {next_action.get('score', 0.0):.2f} — "
                        f"{' -> '.join(next_action.get('path', [])[:4])}"
                    )
        return "\n".join(lines)

    def advance(self, mission, graph) -> bool:
        before = mission.phase
        plan = self.controller.plan(mission, graph, self.tracker)
        if not plan.transitions:
            return False
        mission.phase = plan.transitions[-1].new.value
        return mission.phase != before
