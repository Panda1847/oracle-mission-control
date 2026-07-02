# ORACLE Enterprise Deterministic Planner Design

## Goal

Replace the LLM-led mission loop with a deterministic mission orchestrator that uses AI only as an advisor.

## Scope

This phase introduces the new enterprise root architecture needed for roadmap item `1`:

- `config/` with a policy YAML source of truth
- `core/planner/` for state transitions, retries, fallback, and confidence gating
- `core/policy/` for approval and risk decisions
- `core/orchestrator/` for the deterministic mission manager
- `core/ai/` for advisor-only AI integration

## Compatibility Strategy

The existing `oracle.*` package remains the active CLI/runtime surface. Legacy entrypoints are bridged onto the new root-level enterprise modules so item `1` can land without breaking the rest of the repo.

## Deterministic Control Rules

- The planner defines the mission phase.
- The planner defines the candidate actions.
- The AI may recommend only from those candidates.
- Confidence gating decides whether the recommendation is accepted.
- Retry and fallback behavior is policy-driven from YAML.
- If AI is missing, invalid, or low-confidence, the planner still proceeds.

## Testing Focus

- legal and illegal state transitions
- phase checkpoint advancement
- AI recommendation acceptance and rejection
- retry timeout escalation
- mission resilience when actions fail
