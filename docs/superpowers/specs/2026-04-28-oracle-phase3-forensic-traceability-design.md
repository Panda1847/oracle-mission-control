# ORACLE Phase 3 Forensic Traceability Design

## Goal

Close the remaining Phase 3 forensic gap by making the audit chain fully traversable into replay artifacts.

The replay stack is already largely implemented:

- per-iteration replay artifacts exist
- replay artifacts capture graph before/after, planner context, AI prompt/response, action, stdout/stderr, and ingest delta
- `oracle --replay <mission>` exists
- checkpoint audit events already reference replay artifacts

The remaining gap is provenance continuity across the entire audit trail for a decision cycle.

## Scope

This design covers the remaining Phase 3 work still active in the repository:

- establish a stable replay provenance identifier before execution starts
- attach replay provenance to all audit entries emitted during that decision cycle
- ensure the final replay artifact uses the same identifier
- prove the audit chain is traversable from decision to execution to checkpoint artifact

This design does not reopen packaging or delivery work from Phase 4.

## Existing State

Replay artifacts are currently created at checkpoint time in `core/orchestrator/mission_manager.py`.

That means:

- the replay artifact path is known only at checkpoint creation
- earlier audit entries such as `decision`, `result`, `parse_quarantined`, `plugin_unavailable`, or `safety_block` do not consistently carry a stable replay identifier

Checkpoint events do contain `replay_artifact`, but that is not yet enough to make every audit record in the cycle directly traversable.

## Authority Model

Phase 3 uses these authorities:

- `memory/replay.py` is the only replay artifact store
- `core/orchestrator/mission_manager.py` is the only runtime provenance coordinator
- `oracle/runtime/audit.py` remains the append-only audit chain writer

The mission manager must assign replay provenance context before execution, and the audit logger must remain a generic storage layer rather than inventing provenance on its own.

## Design

### 1. Replay Provenance Context

Each decision cycle gets a replay provenance context before execution begins.

This context must include:

- `replay_id`
- mission name
- branch name
- phase

The same `replay_id` must later be used when the checkpoint replay artifact is written.

### 2. Audit Enrichment

Audit entries written during a decision cycle must automatically include the active replay provenance context.

Required fields:

- `replay_id`
- `replay_phase`
- `replay_branch`

When the artifact path becomes available at checkpoint time, the checkpoint audit record must also include:

- `replay_artifact`

This allows auditors to move from any decision-cycle audit entry to the final replay artifact deterministically.

### 3. Traversability Rule

For a given replay id:

- `decision`
- `result`
- terminal branch records like `parse_quarantined`, `plugin_unavailable`, `safety_block`, or `iteration_checkpoint`

must all share the same replay provenance id for that cycle.

Acceptance rule:

decision -> execution -> evidence/checkpoint is traceable without heuristic matching on timestamps or tool names.

## Components

### `core/orchestrator/mission_manager.py`

Responsibilities:

- create replay provenance context
- enrich audit entries with replay provenance
- carry the same replay id into final replay artifact creation

Expected change level:

- moderate

### `oracle/runtime/audit.py`

Responsibilities:

- remain append-only hash-chain storage
- no provenance generation logic beyond storing enriched payloads

Expected change level:

- none or minimal

### `memory/replay.py`

Responsibilities:

- accept caller-supplied replay ids
- persist artifacts with stable replay identity

Expected change level:

- minimal

## Testing Strategy

### Integration tests

- audit entries for one action cycle share the same replay id
- checkpoint replay artifact uses that same replay id
- a terminal branch such as `plugin_unavailable` or `parse_quarantined` still preserves replay provenance

### Regression checks

- replay CLI still loads and selects artifacts by replay id
- existing checkpoint replay artifact tests still pass
- audit hash chaining remains intact

## Acceptance Criteria

Phase 3 is complete in this repository when all of the following are true:

- every audit entry in a decision cycle carries replay provenance
- replay artifacts reuse the same replay id established before execution
- checkpoint audit records still include the concrete replay artifact path
- tests prove decision -> execution -> checkpoint traversability

## Implementation Recommendation

Finish Phase 3 by enriching the existing mission-manager audit path rather than redesigning replay storage:

- create replay context before action execution
- auto-enrich `_audit_log()` payloads when replay context is active
- pass the same replay id into `_build_replay_payload()` and checkpoint artifact creation
