# ORACLE Phase 4 Product Delivery Design

## Goal

Finish the product-delivery layer so ORACLE is not only executable, but deliverable to operators and analysts as a coherent platform artifact.

Phase 4 in this repository is already partially implemented:

- final mission runs emit a canonical mission package zip
- web and API surfaces can download artifacts
- reporting already produces canonical summary, evidence, intelligence, and package data

The remaining work is delivery polish and analyst usability:

- a structured export directory, not only a zip
- an explicit operator export command
- dashboard panels that render analyst-facing findings, topology, timeline, and replay state from canonical data
- immutable build identity visible in runtime surfaces

## Scope

This design covers the Phase 4 gaps still active in the tree:

- add filesystem export generation under `exports/<mission>/`
- add CLI export command for existing mission state
- enrich control-plane responses so the frontend can render analyst findings and replay data directly
- update the dashboard frontend to show findings, topology summary, timeline, replay, and export/download links
- add immutable build identity with semantic version, git hash, and schema version

This design does not introduce a new reporting authority. It extends the existing canonical reporting path.

## Existing State

Current delivery surfaces:

- `export/package.py` builds a mission package zip
- `api/reports.py` can generate a canonical report bundle
- mission-manager emits `mission_package_zip`
- dashboard and operator APIs expose artifact downloads

Current gaps:

1. There is no export directory layout like `exports/<mission>/...`
2. There is no explicit `oracle export` or `oracle --export` operator surface
3. The frontend still renders raw JSON for overview/evidence and does not provide an analyst findings panel, attack graph summary, or replay panel
4. Build identity is not exposed as immutable runtime metadata at mission start

## Authority Model

Phase 4 uses these authorities:

- `core/reporting/intelligence_report.py` remains the canonical report synthesis authority
- `export/package.py` remains the canonical packaging/export authority
- `api/missions.py` and `api/reports.py` remain the control-plane serialization layer
- `web/frontend/*` remains a presentation layer only

No frontend code may invent a second findings model or recompute risk data from scratch.

## Design

### 1. Structured Export Directory

Add export generation that materializes canonical mission outputs into:

- `exports/<mission>/executive_summary.md`
- `exports/<mission>/findings.json`
- `exports/<mission>/evidence.jsonl`
- `exports/<mission>/provenance.jsonl`
- `exports/<mission>/topology.json`
- `exports/<mission>/replay.jsonl`
- `exports/<mission>/remediation.md`
- `exports/<mission>/package.zip`

These files must derive from canonical report, graph snapshot, replay store, and audit log data.

Acceptance rules:

- export files are deterministic for the same stored mission state
- provenance and replay exports are line-oriented for analyst tooling
- `package.zip` remains aligned with the directory export contents

### 2. Export Command Surface

Add an operator command surface:

- `oracle export --mission <mission>`

This command must generate or refresh the structured export directory for an existing mission snapshot.

Acceptance rules:

- export succeeds without starting a new mission
- command prints the export directory path
- missing mission data fails clearly

### 3. Dashboard Analyst Surfaces

Frontend must render:

- analyst findings panel
  - title
  - host
  - port
  - severity
  - confidence
  - CVEs
  - plugin
  - evidence refs
- attack graph / topology summary
- timeline stream
- replay panel
- artifact download links

The backend serializers should provide presentation-ready data fields where helpful, but canonical values must still come from graph/report state.

Acceptance rules:

- no raw JSON blocks are required to understand the primary findings
- dashboard still works when evidence or replay data is sparse
- artifact download links remain usable

### 4. Build Identity Integration

Add immutable build identity surfaced through:

- `oracle.__init__`
- version/banner helpers
- mission start payload/audit metadata

Required fields:

- semantic version
- git hash
- schema version

Acceptance rules:

- build identity is visible in startup/version surfaces
- build identity is logged at mission start
- build identity is included in control-plane overview data

## Components

### `export/package.py`

Responsibilities:

- canonical export directory generation
- package zip generation

Expected change level:

- moderate

### `oracle/cli/main.py`

Responsibilities:

- add export command routing
- surface build identity in runtime startup

Expected change level:

- moderate

### `api/missions.py`

Responsibilities:

- provide delivery-oriented mission/build metadata
- provide replay summary in overview payload

Expected change level:

- moderate

### `web/frontend/index.html` and `web/frontend/app.js`

Responsibilities:

- render analyst-facing delivery panels from canonical API data

Expected change level:

- moderate

### `oracle/__init__.py`

Responsibilities:

- immutable build identity constants/helpers

Expected change level:

- small

## Testing Strategy

### Unit tests

- export directory generator creates expected files
- build identity helper returns semantic version, git hash, and schema version
- export command fails cleanly on missing mission

### Integration tests

- dashboard overview exposes build identity and replay summary
- dashboard artifacts still download correctly after frontend/backend enrichment
- export command writes structured mission exports from stored mission state

### Regression checks

- mission package zip still contains canonical report data
- replay CLI still works
- report API stays aligned with canonical reporting

## Acceptance Criteria

Phase 4 is complete in this repository when all of the following are true:

- `oracle export --mission <mission>` generates structured exports
- exports directory contains the expected report, evidence, provenance, topology, replay, remediation, and package files
- dashboard renders analyst findings, topology, timeline, replay, and artifact downloads from canonical data
- immutable build identity is visible and logged on mission start
- tests prove delivery surfaces and export generation

## Implementation Recommendation

Finish Phase 4 by extending the existing canonical report and package path:

- build directory exports from stored canonical mission data
- expose richer mission/report metadata through existing API surfaces
- upgrade the frontend from raw JSON blocks to analyst panels
- keep package zip and export directory synchronized from one export builder
