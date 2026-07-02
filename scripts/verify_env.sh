#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 --version
python3 -m compileall -q api core memory oracle plugins queue security telemetry web workers
python3 -m pytest -q

if command -v go >/dev/null 2>&1; then
  (cd runtime-go && go test ./...)
else
  echo "go not installed; skipping runtime-go tests"
fi
