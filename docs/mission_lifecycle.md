# Mission Lifecycle

Mission phases:

- `INIT`
- `DISCOVERY`
- `ENUMERATION`
- `VALIDATION`
- `EXPLOIT_ANALYSIS`
- `POST_PROCESS`
- `REPORTING`
- `COMPLETE`
- `FAILED`
- `PAUSED`

## Lifecycle Rules

- transitions are defined by the deterministic state machine
- policies define allowed tools, retries, fallbacks, and approval floors
- AI can recommend only from the allowed candidate set
- evidence and artifacts are saved throughout the mission, not only at the end
- `EXPLOIT_ANALYSIS` emits `attack_path_generated` events for ranked correlation paths
- `REPORTING` emits `report_generated` events for interim report artifacts

## Replay

Mission events are stored in the event stream and can be replayed for:

- timeline inspection
- operator review
- QA regression
- incident reconstruction
