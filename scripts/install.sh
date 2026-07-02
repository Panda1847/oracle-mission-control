#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"

for bin in nmap curl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Missing: $bin"; exit 1; }
done

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt --break-system-packages
python3 -m pip install -e . --break-system-packages
python3 -c "import oracle; print('ORACLE', oracle.__version__, 'installed OK')"

if command -v go >/dev/null 2>&1; then
  (cd runtime-go && go test ./... >/dev/null)
fi

echo ""
echo "Installation complete."
echo "Next: export NVIDIA_API_KEY=your-key && python oracle.py --demo"
