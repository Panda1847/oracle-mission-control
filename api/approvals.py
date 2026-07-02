"""Approval queue and decision workflow."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Optional
from uuid import uuid4


@dataclass
class ApprovalRequest:
    approval_id: str
    requested_by: str
    requested_role: str
    action: dict
    mission_id: str
    status: str = "pending"
    decided_by: str = ""
    decision: str = ""


class ApprovalQueue:
    """In-memory approval workflow for operator actions."""

    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}

    def submit(self, requested_by: str, requested_role: str, mission_id: str, action: dict) -> ApprovalRequest:
        request = ApprovalRequest(
            approval_id=uuid4().hex,
            requested_by=requested_by,
            requested_role=requested_role,
            mission_id=mission_id,
            action=dict(action),
        )
        self._requests[request.approval_id] = request
        return request

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(approval_id)

    def decide(self, approval_id: str, actor: str, decision: str) -> ApprovalRequest:
        request = self._requests[approval_id]
        request.status = "decided"
        request.decided_by = actor
        request.decision = decision
        return request

    def pending(self) -> list[dict]:
        return [asdict(request) for request in self._requests.values() if request.status == "pending"]

