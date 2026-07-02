#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/.deb-build/oracle-enterprise"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/opt/oracle-enterprise" "$BUILD_DIR/DEBIAN"

cat > "$BUILD_DIR/DEBIAN/control" <<'EOF'
Package: oracle-enterprise
Version: 3.2.0
Section: admin
Priority: optional
Architecture: all
Maintainer: ORACLE Project
Description: ORACLE enterprise mission orchestration platform
EOF

cp -R "$ROOT_DIR"/* "$BUILD_DIR/opt/oracle-enterprise/"
dpkg-deb --build "$BUILD_DIR" "$ROOT_DIR/oracle-enterprise_3.2.0_all.deb"
echo "Built $ROOT_DIR/oracle-enterprise_3.2.0_all.deb"
