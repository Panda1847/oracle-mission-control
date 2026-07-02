# Plugin SDK Guide

Enterprise plugins live under `plugins/<name>/` and must include:

- `plugin.py`
- `manifest.yaml`
- `parser.py`
- `schema.json`
- `tests.py`

## Manifest Fields

- `name`
- `version`
- `category`
- `capabilities`
- `required_binaries`
- `risk_level`
- `expected_artifacts`
- `parser_schema`
- `timeout`
- `retry_policy`
- `confidence_weight`
- `approval_required`

## Runtime Contract

- The planner selects by capability, not by hardcoded plugin name.
- The plugin must build a command string for the runtime layer.
- The parser must return structured data or a structured error payload.
- Binary dependencies are surfaced through plugin health and optional checksum verification.
