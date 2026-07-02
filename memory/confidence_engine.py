"""Confidence scoring for evidence."""

from __future__ import annotations


class ConfidenceEngine:
    """Assigns base confidence by source and applies bounded updates."""

    BASE_BY_PLUGIN = {
        "nmap": 0.91,
        "http": 0.84,
        "fuzz": 0.76,
        "manual": 0.95,
    }

    def score(self, source_plugin: str, observed_confidence: float | None = None) -> float:
        base = float(self.BASE_BY_PLUGIN.get(source_plugin, 0.70))
        if observed_confidence is None:
            return round(base, 4)
        observed = max(0.0, min(1.0, float(observed_confidence)))
        return round((base * 0.65) + (observed * 0.35), 4)

    def merge(self, old_confidence: float, new_confidence: float) -> float:
        return round(min(0.99, max(old_confidence, (old_confidence + new_confidence) / 2.0)), 4)

