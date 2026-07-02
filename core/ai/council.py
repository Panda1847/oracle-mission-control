"""Multi-pass advisory council with deterministic arbitration."""

from __future__ import annotations

from typing import Any, Dict, Iterable


def _is_ready(client) -> bool:
    if client is None:
        return False
    try:
        return bool(getattr(client, "ready"))
    except AttributeError:
        return True
    except Exception:
        return False


def _extract_action(response: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if not isinstance(response, dict):
        return None
    action = response.get("action")
    if isinstance(action, dict):
        return action
    tool = str(response.get("tool", "") or "").strip()
    target = str(response.get("target", "") or "").strip()
    if tool and target:
        return {"tool": tool, "target": target, "args": dict(response.get("args", {}) or {})}
    return None


def _action_key(response: Dict[str, Any] | None) -> str:
    action = _extract_action(response)
    if not action:
        return ""
    tool = str(action.get("tool", "") or "").strip()
    target = str(action.get("target", "") or "").strip()
    return f"{tool}|{target}" if tool and target else ""


def _role_summary(role: str, response: Dict[str, Any] | None, *, chosen_key: str, agreement_count: int, vote_count: int) -> Dict[str, Any]:
    payload = dict(response or {})
    action = _extract_action(payload) or {}
    key = _action_key(payload)
    confidence = float(payload.get("confidence", 0.0) or 0.0)
    return {
        "role": role,
        "action": action,
        "tool": str(action.get("tool", "") or ""),
        "target": str(action.get("target", "") or ""),
        "confidence": confidence,
        "reasoning": str(payload.get("reasoning", "") or ""),
        "expected": str(payload.get("expected", "") or ""),
        "stop_reason": str(payload.get("stop_reason", "") or ""),
        "agrees_with_arbiter": bool(chosen_key and key == chosen_key),
        "agreement_count": int(agreement_count or 0) if chosen_key and key == chosen_key else 0,
        "vote_count": int(vote_count or 0),
    }


class CouncilAdvisorClient:
    """Uses proposer, critic, and verifier passes with deterministic arbitration."""

    def __init__(self, *, primary_client=None, secondary_client=None):
        self.primary = primary_client
        self.secondary = secondary_client
        self.last_council: Dict[str, Any] = {}

    @property
    def ready(self) -> bool:
        return _is_ready(self.primary) or _is_ready(self.secondary)

    def _delegate_for_role(self, role: str):
        if role == "critic" and _is_ready(self.secondary):
            return self.secondary
        if _is_ready(self.primary):
            return self.primary
        if _is_ready(self.secondary):
            return self.secondary
        return None

    def _role_prompt(self, role: str, extra: str) -> str:
        instructions = {
            "proposer": (
                "COUNCIL ROLE: proposer. Choose the strongest next allowed action. "
                "Prefer momentum and concrete evidence."
            ),
            "critic": (
                "COUNCIL ROLE: critic. Challenge the riskiest assumptions. "
                "If the proposer would overreach, select a safer allowed action instead."
            ),
            "verifier": (
                "COUNCIL ROLE: verifier. Select the action most directly supported by the known graph and evidence."
            ),
        }
        base = instructions.get(role, "")
        return f"{extra}\n\n{base}".strip()

    def _call_role(self, role: str, mission, graph, extra: str) -> Dict[str, Any]:
        delegate = self._delegate_for_role(role)
        if delegate is None or not getattr(delegate, "decide", None):
            return {"stop_reason": f"{role}_delegate_unavailable"}
        try:
            response = delegate.decide(mission, graph, self._role_prompt(role, extra))
        except Exception as exc:
            return {"stop_reason": f"{role}_delegate_error:{exc.__class__.__name__}"}
        return dict(response or {})

    def _arbiter(self, outputs: Iterable[tuple[str, Dict[str, Any]]]) -> tuple[str, Dict[str, Any]]:
        materialized = list(outputs)
        votes: Dict[str, list[tuple[str, Dict[str, Any]]]] = {}
        for role, response in materialized:
            key = _action_key(response)
            if not key:
                continue
            votes.setdefault(key, []).append((role, response))

        if votes:
            winner = sorted(
                votes.items(),
                key=lambda item: (
                    len(item[1]),
                    1 if any(role == "verifier" for role, _ in item[1]) else 0,
                    1 if any(role == "proposer" for role, _ in item[1]) else 0,
                    item[0],
                ),
                reverse=True,
            )[0][1]
            chosen_role, chosen_response = sorted(
                winner,
                key=lambda item: (item[0] == "verifier", item[0] == "proposer", item[0] == "critic"),
                reverse=True,
            )[0]
            return chosen_role, dict(chosen_response)

        for preferred_role in ("verifier", "proposer", "critic"):
            for role, response in materialized:
                if role != preferred_role:
                    continue
                if _extract_action(response):
                    return role, dict(response)
        return "none", {"stop_reason": "council_no_recommendation"}

    def decide(self, mission, graph, extra: str = "") -> Dict[str, Any]:
        if not self.ready:
            return {"stop_reason": "council_unavailable"}

        proposer = self._call_role("proposer", mission, graph, extra)
        critic = self._call_role("critic", mission, graph, extra)
        verifier = self._call_role("verifier", mission, graph, extra)
        outputs = [
            ("proposer", proposer),
            ("critic", critic),
            ("verifier", verifier),
        ]
        arbiter_role, chosen = self._arbiter(outputs)
        chosen_key = _action_key(chosen)
        eligible_votes = sum(1 for _, response in outputs if _extract_action(response))
        agreement_count = sum(1 for _, response in outputs if chosen_key and _action_key(response) == chosen_key)
        split_vote = bool(eligible_votes and agreement_count < eligible_votes)
        chosen_action = _extract_action(chosen) or {}
        council_meta = {
            "arbiter": arbiter_role,
            "roles": {
                role: _role_summary(
                    role,
                    response,
                    chosen_key=chosen_key,
                    agreement_count=agreement_count,
                    vote_count=eligible_votes,
                )
                for role, response in outputs
            },
            "consensus": {
                "tool": str(chosen_action.get("tool", "") or ""),
                "target": str(chosen_action.get("target", "") or ""),
                "agreement_count": agreement_count,
                "eligible_votes": eligible_votes,
                "is_unanimous": bool(eligible_votes and agreement_count == eligible_votes),
                "is_split_vote": split_vote,
            },
        }
        out = dict(chosen or {})
        out["council"] = council_meta
        self.last_council = council_meta
        return out
