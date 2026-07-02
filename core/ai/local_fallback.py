"""Deterministic local fallback advisor."""

from __future__ import annotations


class LocalFallbackAdvisor:
    """Heuristic fallback that keeps missions moving even when remote AI is unavailable."""

    def recommend(self, mission, graph, phase: str, candidates, checkpoint_reason: str):
        if not candidates:
            return None
        chosen = sorted(
            candidates,
            key=lambda action: (
                action.tool == "http",
                action.tool == "nmap",
                action.confidence,
                len(str(action.expected or "")),
            ),
            reverse=True,
        )[0]
        return {
            "tool": chosen.tool,
            "target": chosen.target,
            "reasoning": f"Local fallback selected the highest-confidence allowed action during {phase}: {checkpoint_reason}",
            "expected": chosen.expected,
            "confidence": float(chosen.confidence or 0.5),
            "prompt_version": "local-fallback.v1",
        }
