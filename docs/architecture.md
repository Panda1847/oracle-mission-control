# ORACLE Enterprise Architecture

ORACLE is organized around five runtime planes:

1. Control plane
   Handles mission state, operator approvals, dashboards, and APIs.

2. Decision plane
   The deterministic planner and policy system choose legal next actions and phase transitions.

3. Execution plane
   The Go runtime and worker dispatch layer execute plugin commands with isolation and timeouts.

4. Intelligence plane
   The evidence graph stores hosts, services, findings, provenance, confidence, TTL, and contradictions.

5. Assurance plane
   Telemetry, audit, config validation, test harnesses, and report generation make the platform observable and certifiable.

## Failure Containment

- If advisory AI fails, the planner still chooses a legal action.
- If a remote worker fails, the dispatcher falls back to the local worker.
- If a queue consumer fails, the message is placed in the dead-letter queue instead of halting the mission loop.
- If reporting fails, the mission snapshot artifact still persists.

## Primary Runtime Flow

1. MissionManager asks the planner for the next legal phase and candidate actions.
2. AIAdvisor may recommend one candidate, but only from the allowed set.
3. Safety and approval checks run before execution.
4. Dispatcher sends the action to a healthy worker or falls back locally.
5. Executor/plugin output updates the knowledge graph and evidence store.
6. EventBus publishes timeline events to the control plane and replay stream.
7. ArtifactRouter stores mission snapshots and reports.
