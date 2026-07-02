"""Checkpoint rules that control phase advancement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from core.orchestrator.job_tracker import JobTracker
from core.planner.state_machine import MissionPhase, MissionStateMachine
from core.policy.policy_engine import PolicyEngine


@dataclass
class PhaseCheckpoint:
    """Outcome of evaluating a phase checkpoint."""

    ready: bool
    reason: str
    metrics: Dict[str, Any] = field(default_factory=dict)


class TransitionRules:
    """Phase checkpoint evaluation backed by policy and graph state."""

    def __init__(self, policy: PolicyEngine, state_machine: MissionStateMachine):
        self.policy = policy
        self.state_machine = state_machine

    def evaluate(self, phase: MissionPhase, mission, graph, tracker: JobTracker, pending_candidates: int) -> PhaseCheckpoint:
        if phase in {MissionPhase.INIT, MissionPhase.EXPLOIT_ANALYSIS, MissionPhase.POST_PROCESS, MissionPhase.REPORTING}:
            return PhaseCheckpoint(True, "Phase is deterministic and handled by internal orchestration steps.")
        if phase == MissionPhase.COMPLETE:
            return PhaseCheckpoint(True, "Mission complete.")
        if phase == MissionPhase.FAILED:
            return PhaseCheckpoint(True, "Mission failed.")
        if phase == MissionPhase.PAUSED:
            return PhaseCheckpoint(False, "Mission paused.")

        if phase == MissionPhase.DISCOVERY:
            successful_targets = {
                result.action.target
                for result in getattr(graph, "actions", [])
                if result.success
                and result.action.tool == "nmap"
                and result.action.phase == MissionPhase.DISCOVERY.value
            }
            scope_scanned = bool(mission.scope) and all(target in successful_targets for target in mission.scope)
            ready = pending_candidates == 0 and (scope_scanned or len(graph.hosts) > 0)
            return PhaseCheckpoint(
                ready=ready,
                reason="Discovery scans completed." if ready else "Discovery still has pending scan work.",
                metrics={
                    "hosts": len(graph.hosts),
                    "pending_candidates": pending_candidates,
                    "successful_targets": len(successful_targets),
                },
            )

        if phase == MissionPhase.ENUMERATION:
            reviewed = tracker.count_success(phase=MissionPhase.ENUMERATION.value)
            ready = pending_candidates == 0 and len(graph.hosts) > 0
            return PhaseCheckpoint(
                ready=ready,
                reason="Enumeration candidates exhausted." if ready else "Enumeration still has pending service review.",
                metrics={"reviewed_actions": reviewed, "pending_candidates": pending_candidates},
            )

        if phase == MissionPhase.VALIDATION:
            validated = tracker.count_success(phase=MissionPhase.VALIDATION.value)
            ready = pending_candidates == 0
            return PhaseCheckpoint(
                ready=ready,
                reason="Validation pass complete." if ready else "Validation still has pending checks.",
                metrics={"validated_actions": validated, "pending_candidates": pending_candidates},
            )

        return PhaseCheckpoint(False, "No checkpoint rule matched.", {"pending_candidates": pending_candidates})

    def next_phase(self, phase: MissionPhase, checkpoint: PhaseCheckpoint) -> MissionPhase | None:
        if not checkpoint.ready:
            return None
        return self.state_machine.next_linear_phase(phase)
