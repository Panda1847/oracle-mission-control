# ORACLE Phase 5 Advanced Features and AI Design

## Goal

Finish the Phase 5 architecture surfaces that turn ORACLE from a deterministic mission runner into an analyst-grade intelligence product with richer graph semantics, live mission narration, and optional multi-model decision support.

Phase 5 in the build map has three major workstreams:

- `core/attackgraph.py`
- `dashboard/live_stream.py`
- `core/ai/council.py`

This repository should implement them in that order. The first workstream is the authority boundary for the rest of the phase, because live-stream and council decisions should consume one canonical weighted attack-graph model instead of each recomputing their own path logic.

## Scope

This design covers the full Phase 5 direction, with immediate implementation focused on `core/attackgraph.py`.

Included now:

- add an authoritative attack-graph synthesis module
- replace inline attack-graph summary generation in reporting with that module
- expose attack-graph data to dashboard and report-package surfaces from canonical state

Defined for later in the same phase:

- add live mission stream serialization around canonical events and graph deltas
- add AI council orchestration with deterministic arbitration and optional backend selection

Not in scope for this first implementation slice:

- browser-only visualization logic that invents graph weights client-side
- a second report or planner graph format
- model-provider-specific network integrations

## Existing State

Current graph-related behavior is split across multiple layers:

- `core/correlation.py` builds ranked attack-path candidates
- `oracle/memory/graph.py` produces a topology graph for host and service relationships
- `core/reporting/intelligence_report.py` currently fabricates `attack_graph_summary` inline by combining topology counts with correlation paths
- `api/missions.py` forwards a trimmed attack-graph summary to dashboard consumers

Current gaps:

1. There is no authoritative weighted attack-graph object
2. Reporting recomputes graph summary logic locally instead of calling a graph authority
3. Dashboard and exports receive only summary counts and top paths, not a canonical graph object suitable for richer rendering
4. Phase 5 live-stream and AI-council work would currently have to duplicate graph semantics

## Authority Model

Phase 5 uses these authorities:

- `core/correlation.py` remains the authority for deterministic attack-path candidate generation
- `oracle/memory/graph.py` remains the authority for raw topology serialization
- `core/attackgraph.py` becomes the authority that fuses topology, correlation paths, findings, and evidence-derived confidence into one weighted attack-graph object
- `core/reporting/intelligence_report.py` becomes a consumer of `core/attackgraph.py`, not a second graph synthesizer
- `api/missions.py` and export/package surfaces become serializers of canonical attack-graph data only

No other module may invent its own attack-graph weighting or recompute top-path selection from raw graph data unless it delegates to `core/attackgraph.py`.

## Design

### 1. Canonical Attack Graph

Add `core/attackgraph.py` as the authoritative weighted-graph builder.

Inputs:

- graph snapshot / graph-like object
- topology data
- deterministic correlation output from `core/correlation.py`

Output shape:

- `summary`
  - node count
  - edge count
  - candidate count
  - highest path score
  - weighted edge count
- `nodes`
  - stable node id
  - label
  - kind
  - severity
  - weight
  - risk score
  - evidence count
- `edges`
  - stable edge id
  - from
  - to
  - kind
  - weight
  - reasoning
  - supporting finding ids
- `top_paths`
  - ranked correlation paths with stable path ids and normalized score

Weighting rules:

- topology containment and exposure edges are the base graph
- correlation paths raise weights on participating host/service nodes and traversal edges
- finding severity and evidence confidence increase node and edge risk
- contradictions dampen confidence-derived weights rather than removing structure

Acceptance rules:

- equal stored mission state produces equal graph output
- graph ids and ordering are deterministic
- summary fields are derived from the canonical graph object, not recomputed separately

### 2. Reporting Integration

`core/reporting/intelligence_report.py` must call `core/attackgraph.py` and embed its results.

Rules:

- `attack_graph_summary` is derived from the canonical graph object
- a machine-consumable full `attack_graph` object should be available in the report package
- executive summary can still mention the top correlated path, but the path source must come from the canonical attack graph output

### 3. Dashboard and Export Contracts

Control-plane and export surfaces should expose the attack graph in a way that supports future richer visualization without creating a second graph model.

Required contract:

- mission overview keeps lightweight `attack_graph_summary`
- canonical reports and exports include full `attack_graph`
- frontend may render summary-first now, but must read canonical graph fields when available

This keeps today’s dashboard stable while opening the door for a dedicated graph visualization panel later in Phase 5.

### 4. Future Phase 5 Dependencies

The following workstreams depend on the attack-graph contract but are not implemented in this first slice:

- `dashboard/live_stream.py`
  - consumes mission events, graph delta events, findings, and decision narration
  - should serialize graph changes using canonical attack-graph node and edge identifiers
- `core/ai/council.py`
  - proposer / critic / verifier / arbiter flow
  - should consume canonical attack-graph summaries as planner context
  - optional backend mode: `ORACLE_AI_BACKEND=council`

## Components

### `core/attackgraph.py`

Responsibilities:

- build deterministic weighted attack-graph object
- convert correlation paths into canonical graph edges and path metadata
- provide a single public builder used by reporting and control-plane layers

Expected change level:

- moderate

### `core/reporting/intelligence_report.py`

Responsibilities:

- consume canonical attack graph
- stop synthesizing attack-graph summary inline

Expected change level:

- moderate

### `api/missions.py`

Responsibilities:

- expose summary-first attack-graph data from the canonical report object

Expected change level:

- small to moderate

### `tests/unit/test_attackgraph.py`

Responsibilities:

- validate deterministic graph construction, weighting, ordering, and summary integrity

Expected change level:

- new

## Testing Strategy

### Unit tests

- weighted attack graph is built from topology plus correlation paths
- correlation participation increases node and edge weights
- contradictions reduce confidence-derived weight without removing nodes
- empty or topology-only graph still serializes cleanly

### Integration tests

- intelligence report embeds canonical `attack_graph` and summary
- dashboard/control-plane snapshot continues to expose stable summary fields

### Regression checks

- existing correlation planner behavior remains unchanged
- export/report packaging still works with richer graph payloads

## Acceptance Criteria

Phase 5 has started correctly in this repository when all of the following are true:

- `core/attackgraph.py` exists and is the sole weighted attack-graph authority
- intelligence reports embed canonical attack-graph output
- dashboard/report consumers derive attack-graph summary from canonical data
- deterministic tests cover graph weighting, ids, and ordering

The remainder of Phase 5 should then proceed with live stream and AI council work on top of this graph contract.

## Implementation Recommendation

Implement Phase 5 in this order:

1. Build `core/attackgraph.py` and prove deterministic graph output
2. Refactor reporting and control-plane surfaces to consume that module
3. Extend frontend rendering only as needed to display canonical summary data
4. Move to `dashboard/live_stream.py`
5. Finish with `core/ai/council.py` and the optional `ORACLE_AI_BACKEND=council` path
