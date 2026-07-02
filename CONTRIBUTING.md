# Contributing to ORACLE

Thanks for considering a contribution. This project takes the
scope-guard/policy layer seriously — please read the note at the bottom
before opening a plugin PR.

## Getting set up

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pip install -e .
cd runtime-go && go mod download && cd ..
make ci
```

`make ci` should be green before you branch and green again before you
open a PR.

## Workflow

1. Fork, branch off `main`.
2. Keep PRs focused — one feature/fix per PR is much easier to review
   than a bundle.
3. Add or update tests under `tests/unit`, `tests/integration`, or
   `tests/replay` for any behavior change.
4. Run `make ci` locally.
5. Open a PR describing *what* changed and *why*. Link any related issue.

## Adding a plugin

Plugins are manifest-driven — see [`docs/plugin_sdk.md`](docs/plugin_sdk.md)
for the interface. New plugins must:

- Declare a manifest (`manifest.yaml`) with an explicit risk level.
- Go through the existing scope guard / policy engine like every other
  action — do not bypass it, even for "read-only" plugins.
- Ship a `tests.py` alongside the plugin covering at least parse-success
  and parse-failure cases.

## Code style

- Python: `black` + `isort` (both in `requirements-dev.txt`).
- Go: standard `gofmt`.
- Type hints on new/changed Python functions where practical.

## Reporting bugs / requesting features

Use the issue templates. For anything security-sensitive, see
[`SECURITY.md`](.github/SECURITY.md) instead of opening a public issue.
