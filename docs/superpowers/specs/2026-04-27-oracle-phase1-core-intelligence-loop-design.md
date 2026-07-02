# ORACLE Phase 1 Core Intelligence Loop Design

## Goal

Complete Phase 1 from the build map by making ORACLE intellectually complete, not merely operational.

Phase 1 finishes one authoritative loop:

`KnowledgeGraph -> correlation synthesis -> planner phase intelligence -> mission-manager internal phase execution -> structured reporting -> graph/storage`

This phase must produce real attack candidates, real exploit-analysis outputs, real reporting artifacts, and deterministic state transitions without introducing duplicate planning or reporting authorities.

## Scope

This design covers the full Phase 1 slice authorized by the user:

- finish and harden `core/correlation.py`
- carry correlation outputs through planner views and exploit-phase decision helpers
- ensure engine internal phases perform non-empty work through `EXPLOIT_ANALYSIS`, `POST_PROCESS`, and `REPORTING`
- synthesize and persist a final structured intelligence report
- verify the same authoritative outputs are visible through mission events and graph storage

This design does not include Phase 2 infrastructure hardening, event-bus async fixes, or unrelated refactors.

## Existing State

The repository already contains partial Phase 1 implementation:

- `core/correlation.py` already builds attack candidates, links related findings, propagates confidence, and ranks paths
- `core/planner/phase_controller.py` and `oracle/core/planner.py` already consume ranked attack paths
- `core/orchestrator/mission_manager.py` already executes internal `EXPLOIT_ANALYSIS`, `POST_PROCESS`, and `REPORTING` phases
- `core/reporting/intelligence_report.py` already builds a structured intelligence report
- integration tests already assert `attack_path_generated`, `report_generated`, and `latest_report`

The problem is not total absence of Phase 1. The problem is that Phase 1 is only partially closed and still needs contract hardening, consistency checks, and explicit authoritative boundaries so the repo does not drift into parallel implementations.

## Authority Model

Phase 1 will use one authority path.

### Authoritative state

`oracle/memory/graph.py::KnowledgeGraph` is the authoritative mission intelligence state.

It owns:

- hosts
- findings
- evidence snapshot access
- reports persisted for the mission

No planner, correlation helper, or reporting module should become a shadow owner of mission state.

### Authoritative synthesis stages

- `core/correlation.py` is the authoritative attack-path synthesizer
- `core/planner/phase_controller.py` is the authoritative deterministic phase/candidate controller
- `core/orchestrator/mission_manager.py` is the authoritative phase execution surface
- `core/reporting/intelligence_report.py` is the authoritative final intelligence synthesis builder

### Compatibility surfaces

`oracle/core/planner.py` and `oracle/core/engine.py` remain compatibility facades only. They may expose Phase 1 outputs, but they must not create an alternate control path.

## Phase 1 Design

### 1. Correlation Module

`core/correlation.py` remains the single attack-candidate engine for exploit analysis.

It must deterministically:

- consume graph hosts and findings
- use related-finding linkage to connect local evidence
- propagate confidence without mutating graph state
- produce ranked exploit-path candidates
- emit stable, machine-usable fields: `path`, `score`, `reason`, `finding_ids`

### Required behaviors

- same input graph state must produce the same ranked outputs
- empty or weak graph state must return an empty candidate list, not malformed records
- ranking must remain deterministic on ties
- confidence propagation must never exceed `[0.0, 1.0]`
- candidate reasons must explain why the path exists, not just that it was ranked

### Data contract

Each candidate must be shaped like:

```json
{
  "path": ["10.0.0.5:web:80", "10.0.0.5:smb:445"],
  "score": 0.81,
  "reason": "credential relay probable",
  "finding_ids": ["f1", "f2"]
}
```

### 2. Planner Integration

The planner must consume correlation outputs instead of merely exposing phase names.

### Required planner intelligence surfaces

The planner view must explicitly surface:

- graph state summary
- unresolved findings count
- confidence gaps
- ranked attack candidates
- a deterministic `next_exploit_action()` preview

### Required behavior

- if the mission phase is `EXPLOIT_ANALYSIS`, the planner must expose the top ranked attack paths
- if attack paths exist, `next_exploit_action()` must return the top deterministic path preview
- if no attack paths exist, the planner must return a valid empty structure instead of stale data
- planner outputs must derive from current graph state only

### Boundary rule

Planner code may describe and select from attack candidates, but candidate synthesis still belongs only to `core/correlation.py`.

### 3. Engine Hooks and Internal Phase Execution

`core/orchestrator/mission_manager.py` remains the only place where internal phases execute.

### EXPLOIT_ANALYSIS

This phase must:

- call `build_attack_candidates()` and `rank_attack_paths()`
- convert top attack paths into correlation findings when appropriate
- emit `attack_path_generated` events for generated paths
- include ranked attack paths in the `phase_internal` payload

Acceptance rule:

`EXPLOIT_ANALYSIS` must not be an empty pass-through when meaningful graph state exists.

### POST_PROCESS

This phase must:

- prune expired evidence if available
- surface contradiction counts
- persist graph state after internal cleanup

Acceptance rule:

post-process output must be structured and deterministic, not an implicit side effect.

### REPORTING

This phase must:

- build mission summary
- build evidence export
- build intelligence report
- build machine bundle export
- persist the intelligence report back into the graph
- write reporting artifacts
- emit `report_generated` events for each generated artifact

Acceptance rule:

reporting must produce a canonical latest report in graph/storage and a stable artifact set from the same source data.

### 4. Reporting Module

`core/reporting/intelligence_report.py` is the formal intelligence-synthesis module for Phase 1.

It must create:

- executive summary
- ranked findings
- top hosts
- attack graph summary
- remediation text
- machine JSON package

### Reporting source-of-truth rule

The report must be derived from one graph snapshot captured during reporting. Reporting must not recompute from a second state source or hand-build a conflicting summary elsewhere.

### Machine package rule

The machine package must be suitable for later automation and must include:

- mission identifier
- generation time
- stats
- ranked findings
- top hosts
- attack graph summary
- remediation
- mission snapshot metadata

## Components

### `oracle/memory/graph.py`

Responsibilities:

- authoritative mission intelligence state
- persisted latest report storage
- event emission for report storage

Expected change level:

- minimal, unless a small helper is needed to make Phase 1 persistence clearer

### `core/correlation.py`

Responsibilities:

- related-finding linkage
- confidence propagation
- attack candidate generation
- deterministic attack path ranking

Expected change level:

- moderate hardening and contract tightening

### `core/planner/phase_controller.py`

Responsibilities:

- deterministic phase descriptions
- exploit-analysis visibility into attack candidates
- candidate-aware phase narration

Expected change level:

- moderate

### `oracle/core/planner.py`

Responsibilities:

- compatibility facade
- expose `next_exploit_action()` and exploit-phase summaries through the legacy path

Expected change level:

- small, limited to compatibility completeness

### `core/orchestrator/mission_manager.py`

Responsibilities:

- authoritative internal phase execution
- attack path event emission
- report generation orchestration
- persistence of final structured report

Expected change level:

- moderate, focused on making internal phases explicit and non-empty

### `core/reporting/intelligence_report.py`

Responsibilities:

- canonical final intelligence synthesis
- machine package creation

Expected change level:

- moderate hardening and schema completion

## Data Flow

1. Executor-driven discovery and validation populate `KnowledgeGraph`.
2. `EXPLOIT_ANALYSIS` reads current graph state and builds ranked attack candidates through `core/correlation.py`.
3. Planner surfaces attack candidates, unresolved findings, and confidence gaps from that same graph state.
4. `MissionManager` executes internal exploit-analysis work and emits `attack_path_generated`.
5. `POST_PROCESS` normalizes/persists graph state.
6. `REPORTING` captures one graph snapshot and builds summary, evidence export, intelligence report, and bundle export from that snapshot.
7. The intelligence report is stored back into the graph as the canonical `latest_report`.
8. Artifact paths and report-generation events are emitted from the same reporting run.

## Error Handling

- Missing hosts or findings must degrade to empty correlation/reporting outputs, not exceptions
- Correlation helpers must not mutate graph state directly
- Reporting must tolerate sparse topology/evidence data and still return a valid report object
- Internal phases must return structured payloads even when no work is available
- Compatibility wrappers must never invent alternate outputs when enterprise modules already produced canonical results

## Testing Strategy

### Unit tests

- correlation linkage between same-host and same-port findings
- confidence propagation raises weak related findings without exceeding bounds
- attack candidate generation returns stable fields and deterministic ranking
- intelligence report always includes all required sections
- machine package contains the expected mission snapshot metadata

### Integration tests

- mission run with seeded graph state enters `EXPLOIT_ANALYSIS` and emits `attack_path_generated`
- exploit-analysis adds correlation findings derived from ranked paths
- reporting emits `report_generated` events for summary, evidence, intelligence, and bundle artifacts
- `graph.latest_report()` matches the report built during reporting

### Regression checks

- no duplicate planning authority introduced under `oracle/core/*`
- no stale report created from a different state snapshot than the stored one
- no empty exploit-analysis pass when viable attack candidates exist

## Acceptance Criteria

Phase 1 is complete when all of the following are true:

- correlation has one authoritative implementation
- planner surfaces graph state, unresolved findings, confidence gaps, ranked attack candidates, and `next_exploit_action()`
- mission-manager internal phases perform explicit work for `EXPLOIT_ANALYSIS`, `POST_PROCESS`, and `REPORTING`
- exploit analysis emits `attack_path_generated`
- reporting emits `report_generated`
- a canonical structured intelligence report is persisted into graph/storage
- tests prove the same authority path from graph state through final report

## Non-Goals

- Phase 2 event-bus async hardening
- broad filesystem or runtime architecture cleanup
- moving authority away from `KnowledgeGraph`
- introducing a second planner or second reporting stack

## Implementation Recommendation

Implement by converging on the already-present enterprise modules rather than adding new duplicate ones.

This means:

- harden and complete existing Phase 1 modules
- preserve `oracle/*` compatibility facades
- reject any change that creates a second source of truth for attack candidates, phase execution, or final reporting
