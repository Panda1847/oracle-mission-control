"""Turns the existing LLM client into a non-authoritative advisor."""

from __future__ import annotations

from core.ai.model_router import ModelRouter
from core.ai.prompt_templates import build_advisor_context
from core.ai.response_validator import RecommendationValidator


class AIAdvisor:
    """Wraps an AI client and returns sanitized recommendations only."""

    def __init__(self, client=None):
        self.router = ModelRouter(client)
        self.validator = RecommendationValidator()
        self.last_exchange = {
            "backend": str(getattr(self.router, "backend", "auto")),
            "prompt": "",
            "raw_response": None,
            "validated_recommendation": None,
            "source": "none",
        }

    def recommend(self, mission, graph, phase: str, candidates, checkpoint_reason: str, advisor_state: dict | None = None):
        if not candidates:
            self.last_exchange = {
                "backend": str(getattr(self.router, "backend", "auto")),
                "prompt": "",
                "raw_response": None,
                "validated_recommendation": None,
                "source": "none",
            }
            return None
        client = self.router.active()
        fallback = self.router.fallback()
        fallback_allowed = client is fallback or not getattr(client, "ready", True)
        extra = build_advisor_context(phase, candidates, checkpoint_reason, advisor_state=advisor_state or {})
        self.last_exchange = {
            "backend": str(getattr(self.router, "backend", "auto")),
            "prompt": extra,
            "raw_response": None,
            "validated_recommendation": None,
            "source": "primary",
        }
        if getattr(client, "decide", None):
            try:
                response = client.decide(mission, graph, extra)
                self.last_exchange["raw_response"] = response
                validated = self.validator.validate(response, candidates)
                if validated:
                    self.last_exchange["validated_recommendation"] = validated
                    return validated
            except Exception:
                self.last_exchange["source"] = "primary_error"
                if not fallback_allowed:
                    return None
        if fallback_allowed and getattr(fallback, "recommend", None):
            recommendation = fallback.recommend(mission, graph, phase, candidates, checkpoint_reason)
            self.last_exchange["source"] = "fallback"
            self.last_exchange["raw_response"] = recommendation
            self.last_exchange["validated_recommendation"] = recommendation
            return recommendation
        self.last_exchange["source"] = "none"
        return None
