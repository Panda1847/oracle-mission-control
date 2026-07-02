# Security Notes

ORACLE currently includes:

- signed worker/job payloads
- encrypted secret storage with Fernet
- optional mTLS context builders for worker transport
- plugin sandbox command allowlists
- binary presence and checksum verification helpers
- immutable audit chain for operator actions

These controls are designed so a single failed security subsystem degrades safely instead of crashing the mission framework.
