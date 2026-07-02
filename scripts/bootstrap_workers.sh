#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from workers.agent import WorkerAgent

agent = WorkerAgent(worker_id="local-bootstrap", capabilities=["nmap", "http", "fuzz"])
agent.start()
print(agent.endpoint)
try:
    input("Worker running. Press Enter to stop...\n")
finally:
    agent.stop()
PY
