# ORACLE Community Edition — Repo-Aligned Definitive Execution Plan

This document supersedes `ORACLE_COMMUNITY_WORKFLOW.md` for this repository state.

## Architecture Lock (Do Not Change)

- State machine: `INIT -> DISCOVERY -> ENUMERATION -> VALIDATION -> EXPLOIT_ANALYSIS -> POST_PROCESS -> REPORTING -> COMPLETE | FAILED | PAUSED`
- Council model: `proposer / critic / verifier` with deterministic confidence-gate fallback
- Plugin execution contract: sync `ToolPlugin.build()` / `ToolPlugin.parse()` plus manifest-driven registry

## Status Legend

- `[DONE]` implemented and working in current codebase
- `[PARTIAL]` implemented but incomplete, fragile, or missing required hardening
- `[MISSING]` not implemented in current codebase

## Phase 1 — Community Identity and Edition Framework

- `[MISSING]` Community/Pro edition framework module is not implemented (`oracle/core/edition.py` does not exist).
- `[MISSING]` Feature-gating decorator (for example `@requires_pro`) is not implemented.
- `[MISSING]` Edition constants are not exposed in `oracle/core/config.py`.
- `[PARTIAL]` CLI versioning exists, but no community/pro branding split or licensing banner flow.

## Phase 2 — Capability Gating and Safety Boundaries

- `[DONE]` Runtime enforces a strict tool whitelist (`nmap/http/fuzz`) and blocked-command patterns. Evidence: `oracle/runtime/safety.py`.
- `[DONE]` Scope checks are enforced before every execution path in mission loop. Evidence: mission manager + scope guard wrapper.
- `[MISSING]` Pro gate interception framework (`core/policy/license_gate.py`) is not present.
- `[MISSING]` Feature-by-feature offensive capability gating policy is not implemented.
- `[MISSING]` `COMMUNITY_CAPABILITY_MANIFEST.md` does not exist.
- `[PARTIAL]` Codebase is mostly recon/analysis-first already, but no formal edition-aware execution policy boundary is enforced.

## Phase 3 — Public Release Hardening and Secret Hygiene

- `[PARTIAL]` `.env` and `.oracle-artifacts` are ignored, but `.oracle/` runtime state is not ignored in root `.gitignore`.
- `[DONE]` No embedded private keys were observed in core paths; CI/test posture is generally clean.
- `[MISSING]` Automated secret scan command set is not integrated into CI/release pipeline.
- `[PARTIAL]` `.env.example` exists but should be reviewed against current runtime keys (`NVIDIA_API_KEY`, `ORACLE_AI_BACKEND`, worker secret settings).

## Phase 4 — Scope Guard Hardening for Community

- `[DONE]` Scope and command safety validator exists and is active in live loop.
- `[PARTIAL]` Current behavior allows empty scope to run (demo/test convenience), which conflicts with desired default-deny community policy.
- `[MISSING]` Interactive `scope add --confirm-authorized` CLI flow is not implemented.
- `[MISSING]` First-class scope checksum/tamper-detection workflow is not implemented.
- `[PARTIAL]` Metadata endpoint and dangerous target denylist can be expanded; current blocked patterns are command-level, not endpoint-policy level.

## Phase 5 — Community Value Features (Intelligence and Passive Recon)

- `[DONE]` CVE intelligence engine exists with offline DB and optional online enrichment. Evidence: `oracle/core/intelligence.py`, `oracle/cli/cve_update.py`.
- `[PARTIAL]` CVE enrichment exists but does not yet implement the full community narrative package (CISA KEV flagging, vendor-advisory links, formal remediation bundles).
- `[MISSING]` Passive OSINT plugin suite (`plugins/passive/*`) is not implemented.
- `[PARTIAL]` Attack graph and topology visualization are strong in dashboard/reporting, but dedicated community-focused attack-surface UX remains incomplete.

## Phase 6 — Reporting and Export UX

- `[DONE]` JSON/HTML/PDF and mission package exports are implemented. Evidence: `core/reporting/*`, `oracle/cli/export.py`, `export/package.py`.
- `[DONE]` Dashboard and control plane expose artifacts and download links.
- `[PARTIAL]` Community-branded report narrative and explicit "execution gated" messaging are not integrated.
- `[PARTIAL]` Demo report quality is good but not tailored to community conversion flow.

## Phase 7 — Installer and Doctor Experience

- `[PARTIAL]` `oracle doctor` is implemented and checks key runtime components.
- `[PARTIAL]` `install.sh` exists, but not yet aligned to a polished one-command multi-distro community installer spec.
- `[MISSING]` Explicit first-run onboarding workflow with legal acceptance and scope setup is not implemented.
- `[PARTIAL]` Selftest exists (`oracle/runtime/selftest.py`) but should be incorporated into install completion flow.

## Phase 8 — Community Demo Mode

- `[DONE]` Demo mode runs with no API key and no external tools using simulated graph injection.
- `[PARTIAL]` Demo does not yet run a full council/mission-manager lifecycle in community framing.
- `[MISSING]` Demo does not trigger a formal pro gate event path because license gate module/events are absent.
- `[PARTIAL]` Demo output artifacts exist, but no dedicated `community_demo.html` conversion narrative workflow is wired.

## Phase 9 — Legal and Compliance Integration

- `[MISSING]` `LICENSE.md`, `TERMS_OF_SERVICE.md`, `ACCEPTABLE_USE_POLICY.md` are not present in repo root.
- `[MISSING]` First-run "I AGREE" legal acceptance flow is not implemented in CLI.
- `[MISSING]` Acceptance record file (`.oracle/acceptance.json`) and ToS hash tracking are not implemented.
- `[MISSING]` `--skip-legal` + `ORACLE_ACCEPT_TERMS=true` CI override flow is not implemented.

## Phase 10 — Community Documentation and GitHub Readiness

- `[DONE]` Base README exists.
- `[MISSING]` Community-specific README rewrite is not implemented.
- `[MISSING]` `CONTRIBUTING.md` is not present.
- `[MISSING]` `SECURITY.md` is not present.
- `[PARTIAL]` GitHub Actions workflow exists but does not yet include full lint + bandit matrix requested by community workflow.
- `[MISSING]` Issue and PR templates are not present under `.github/`.

## Definitive Pre-Release Priority Queue (Community)

- `[P0][MISSING]` Build edition framework (`oracle/core/edition.py`) and enforce `@requires_pro` gates.
- `[P0][MISSING]` Implement `core/policy/license_gate.py` and wire `critical_vulnerability_found` path.
- `[P0][PARTIAL]` Convert scope model to default-deny for community mode with explicit authorization acknowledgment flow.
- `[P0][MISSING]` Add legal docs and first-run legal acceptance capture.
- `[P1][MISSING]` Implement passive OSINT plugin family in `plugins/passive/` with evidence attribution.
- `[P1][PARTIAL]` Upgrade community demo to include pro-gate showcase and end-to-end story artifacts.
- `[P1][MISSING]` Add community docs set (`README`, `CONTRIBUTING`, `SECURITY`, capability manifest).
- `[P2][PARTIAL]` Expand CI for lint/security/reporting and add release guardrails for secrets.

