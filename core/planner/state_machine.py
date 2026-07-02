"""Mission phase definitions and deterministic transitions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MissionPhase(str, Enum):
    INIT = "INIT"
    DISCOVERY = "DISCOVERY"
    ENUMERATION = "ENUMERATION"
    VALIDATION = "VALIDATION"
    EXPLOIT_ANALYSIS = "EXPLOIT_ANALYSIS"
    POST_PROCESS = "POST_PROCESS"
    REPORTING = "REPORTING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    PAUSED = "PAUSED"


LEGACY_PHASE_MAP = {
    "recon": MissionPhase.DISCOVERY,
    "enum": MissionPhase.ENUMERATION,
    "exploit": MissionPhase.EXPLOIT_ANALYSIS,
    "post": MissionPhase.POST_PROCESS,
    "report": MissionPhase.REPORTING,
    "paused": MissionPhase.PAUSED,
    "complete": MissionPhase.COMPLETE,
    "stopped": MissionPhase.FAILED,
}


TRANSITION_MAP = {
    MissionPhase.INIT: {MissionPhase.DISCOVERY, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.DISCOVERY: {MissionPhase.ENUMERATION, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.ENUMERATION: {MissionPhase.VALIDATION, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.VALIDATION: {MissionPhase.EXPLOIT_ANALYSIS, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.EXPLOIT_ANALYSIS: {MissionPhase.POST_PROCESS, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.POST_PROCESS: {MissionPhase.REPORTING, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.REPORTING: {MissionPhase.COMPLETE, MissionPhase.FAILED, MissionPhase.PAUSED},
    MissionPhase.PAUSED: {
        MissionPhase.INIT,
        MissionPhase.DISCOVERY,
        MissionPhase.ENUMERATION,
        MissionPhase.VALIDATION,
        MissionPhase.EXPLOIT_ANALYSIS,
        MissionPhase.POST_PROCESS,
        MissionPhase.REPORTING,
        MissionPhase.FAILED,
    },
    MissionPhase.COMPLETE: set(),
    MissionPhase.FAILED: set(),
}


LINEAR_ORDER = [
    MissionPhase.INIT,
    MissionPhase.DISCOVERY,
    MissionPhase.ENUMERATION,
    MissionPhase.VALIDATION,
    MissionPhase.EXPLOIT_ANALYSIS,
    MissionPhase.POST_PROCESS,
    MissionPhase.REPORTING,
    MissionPhase.COMPLETE,
]


@dataclass(frozen=True)
class PhaseTransition:
    """A single deterministic state transition."""

    old: MissionPhase
    new: MissionPhase
    reason: str


class MissionStateMachine:
    """Normalizes and validates mission phase transitions."""

    def normalize(self, phase: str | MissionPhase | None) -> MissionPhase:
        if isinstance(phase, MissionPhase):
            return phase
        if not phase:
            return MissionPhase.INIT
        text = str(phase).strip()
        if text in MissionPhase._value2member_map_:
            return MissionPhase(text)
        return LEGACY_PHASE_MAP.get(text.lower(), MissionPhase.INIT)

    def can_transition(self, current: str | MissionPhase, new: str | MissionPhase) -> bool:
        current_phase = self.normalize(current)
        new_phase = self.normalize(new)
        return new_phase in TRANSITION_MAP[current_phase]

    def transition(
        self,
        current: str | MissionPhase,
        new: str | MissionPhase,
        reason: str,
    ) -> PhaseTransition:
        current_phase = self.normalize(current)
        new_phase = self.normalize(new)
        if not self.can_transition(current_phase, new_phase):
            raise ValueError(f"Illegal transition: {current_phase.value} -> {new_phase.value}")
        return PhaseTransition(old=current_phase, new=new_phase, reason=reason)

    def next_linear_phase(self, current: str | MissionPhase) -> MissionPhase | None:
        current_phase = self.normalize(current)
        try:
            idx = LINEAR_ORDER.index(current_phase)
        except ValueError:
            return None
        if idx + 1 >= len(LINEAR_ORDER):
            return None
        return LINEAR_ORDER[idx + 1]

