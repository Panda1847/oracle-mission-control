# Security Policy

## Scope

ORACLE is a security-testing orchestration platform. This policy covers
vulnerabilities *in ORACLE itself* — its planner, policy/approval engine,
scope guard, worker/queue infrastructure, web control plane, and plugins
shipped in this repo. It does not cover misuse of ORACLE against systems
you don't have authorization to test — that is a user responsibility, not
a project vulnerability.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via [GitHub Security Advisories]
(Security tab → "Report a vulnerability") or email [security contact
email]. Include:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal repro is ideal).
- Which component is affected (planner, scope guard, worker dispatch,
  web API, a specific plugin, etc.).

## What to expect

- Acknowledgment within a reasonable timeframe.
- An assessment of severity and, if confirmed, a fix timeline.
- Credit in the release notes if you'd like it, once a fix ships.

## Particularly high-priority reports

Anything that lets an action execute **outside the declared scope**, or
that lets a lower-privilege operator bypass the approval engine, is
treated as critical — these are the core safety guarantees of the
platform. Report these immediately via the private channel above.
