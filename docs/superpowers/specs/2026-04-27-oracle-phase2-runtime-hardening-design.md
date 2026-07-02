# ORACLE Phase 2 Runtime Hardening Design

## Goal

Close the remaining Phase 2 enterprise-hardening gaps by making runtime validation authoritative at startup and eliminating duplicate event-bus implementations that can drift.

Phase 2 in this repository is already partially implemented:

- async event-bus dispatch exists
- worker-secret hardening exists
- `oracle --doctor` exists
- `oracle --selftest` exists

The remaining work is not more scaffolding. The remaining work is convergence and enforcement.

## Scope

This design covers the unresolved Phase 2 items that are still active in the tree:

- make runtime validation execute as a real mission-start preflight, not only an optional doctor command
- keep `doctor`, `selftest`, and startup checks on the same authority path
- eliminate the duplicated root-level queue implementation as a second event-bus authority
- preserve compatibility for any legacy imports that still reference `queue.*`

This design does not reopen Phase 1 intelligence work, replay work, or product packaging work.

## Existing State

The codebase already has most of the raw Phase 2 modules:

- `oracle/runtime/config_validator.py`
- `oracle/runtime/selftest.py`
- `workers/auth.py`
- `oracle/queue/redis_bus.py`

The remaining gaps are:

1. `RuntimeConfigValidator` says it is used for startup checks, but live mission startup does not call it.
2. There are two queue implementations:
   - `oracle/queue/*` is the active enterprise path
   - `queue/*` is a duplicated root copy
3. The duplicated queue copy already drifted from the enterprise implementation.

That duplicate state is enterprise-blocking because Phase 2 is supposed to harden infrastructure, not leave two behaviorally different bus implementations in the repo.

## Authority Model

Phase 2 uses these authorities:

- `oracle/runtime/config_validator.py` is the only runtime validation engine
- `oracle/runtime/selftest.py` is the only integrated self-test harness
- `oracle/queue/*` is the only queue and event-bus implementation
- `core/orchestrator/event_bus.py` remains the event-bus facade that consumes `oracle.queue`

The root-level `queue/*` package becomes compatibility-only. It must not keep its own logic.

## Design

### 1. Startup Preflight Enforcement

Live mission startup must run the same validator used by `oracle --doctor`.

Required checks must block mission start when they fail.
Config-only and optional checks may warn without blocking.

Acceptance rules:

- starting a live mission with a bad worker secret fails before mission execution
- starting a live mission with missing plugin binaries fails before mission execution
- startup checks do not require remote AI credentials when deterministic fallback is valid
- startup warnings remain visible to the operator

### 2. Queue Authority Convergence

`oracle/queue/*` remains the only implementation.

The root-level `queue` package must stop carrying a second copy of:

- `event_stream.py`
- `redis_bus.py`

Instead, root-level imports must re-export the authoritative `oracle.queue` implementations.

Acceptance rules:

- no behavior difference exists between `queue.redis_bus.RedisQueueBus` and `oracle.queue.redis_bus.RedisQueueBus`
- diagnostics, worker-pool sizing, and slow-subscriber tracking are visible through both import paths
- no test depends on stale root-level queue logic

### 3. Runtime Contract Alignment

`doctor`, `selftest`, and startup preflight must all derive their required checks from the same validator implementation.

Acceptance rules:

- a required validation failure produces the same failure reason across doctor and startup
- self-test continues to layer smoke checks on top of validator results instead of reinventing configuration validation
- tests cover both the direct validator path and live mission startup behavior

## Components

### `oracle/runtime/config_validator.py`

Responsibilities:

- authoritative preflight checks
- reusable failure details for doctor and startup

Expected change level:

- small

### `oracle/cli/main.py`

Responsibilities:

- invoke startup preflight before live mission execution
- surface blocking and warning checks clearly

Expected change level:

- moderate

### `oracle/queue/*`

Responsibilities:

- authoritative queue/event-stream implementation

Expected change level:

- minimal unless small export helpers are useful

### `queue/*`

Responsibilities:

- compatibility re-exports only

Expected change level:

- moderate simplification

## Testing Strategy

### Unit tests

- startup preflight blocks on required failures
- startup preflight ignores config-only warnings
- root-level queue imports expose diagnostics from the authoritative implementation

### Regression checks

- `doctor` still behaves as before for strict and non-strict checks
- self-test still runs without duplicating validator logic
- queue bus diagnostics remain available after compatibility convergence

## Acceptance Criteria

Phase 2 is complete in this repository when all of the following are true:

- runtime validation is enforced at live mission startup
- `doctor`, `selftest`, and startup share one validation authority
- root-level queue modules no longer contain duplicate logic
- tests prove queue compatibility and startup enforcement

## Implementation Recommendation

Finish Phase 2 by converging on the existing modules rather than adding new ones:

- route startup enforcement through `RuntimeConfigValidator`
- collapse `queue/*` into compatibility exports of `oracle.queue`
- preserve all current CLI and orchestrator entrypoints
