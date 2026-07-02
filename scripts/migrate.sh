#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from pathlib import Path
from storage.db import Database

db = Database(Path.cwd() / ".oracle-enterprise" / "metadata.sqlite3")
print(f"Initialized database at {db.path}")
PY
