#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf "%s\n" "$*"; }
die() { say "ERROR: $*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

detect_os() {
  local uname_s
  uname_s="$(uname -s 2>/dev/null || true)"
  if [[ "$uname_s" == "Darwin" ]]; then
    echo "macos"
    return 0
  fi
  if [[ "$uname_s" == "Linux" ]]; then
    if [[ -f /etc/os-release ]]; then
      # shellcheck disable=SC1091
      . /etc/os-release
      case "${ID:-}" in
        ubuntu) echo "ubuntu" ;;
        debian) echo "debian" ;;
        kali) echo "debian" ;;
        *) echo "linux-unknown" ;;
      esac
      return 0
    fi
    echo "linux-unknown"
    return 0
  fi
  echo "unknown"
}

install_deps_apt() {
  local sudo_cmd=""
  if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "sudo not found; run as root or install sudo."
    sudo_cmd="sudo"
  fi

  say "[*] Installing system dependencies via apt..."
  $sudo_cmd apt-get update -y || die "apt-get update failed"
  $sudo_cmd apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    nmap curl gobuster ffuf \
    || die "apt-get install failed"

  # Optional wordlists (best-effort)
  $sudo_cmd apt-get install -y --no-install-recommends seclists wordlists >/dev/null 2>&1 || true
}

install_deps_brew() {
  need_cmd brew
  say "[*] Installing system dependencies via Homebrew..."
  brew update >/dev/null 2>&1 || true
  brew install python nmap gobuster ffuf || die "brew install failed"
}

setup_venv() {
  need_cmd python3
  say "[*] Creating venv at ${ROOT_DIR}/.venv"
  python3 -m venv "${ROOT_DIR}/.venv" || die "Failed to create venv"
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.venv/bin/activate"
  python -m pip install -U pip setuptools wheel || die "pip bootstrap failed"
}

install_oracle() {
  local with_web="${ORACLE_WITH_WEB:-1}"
  cd "$ROOT_DIR"
  if [[ "$with_web" == "1" ]]; then
    say "[*] Installing ORACLE (with web extras)..."
    python -m pip install --retries 5 --timeout 30 -e ".[web]" || die "pip install failed"
  else
    say "[*] Installing ORACLE (core only)..."
    python -m pip install --retries 5 --timeout 30 -e . || die "pip install failed"
  fi
}

main() {
  local os
  os="$(detect_os)"

  say "[*] ORACLE installer"
  say "    Repo: ${ROOT_DIR}"
  say "    Detected OS: ${os}"

  case "$os" in
    ubuntu|debian)
      need_cmd apt-get
      install_deps_apt
      ;;
    macos)
      if ! command -v brew >/dev/null 2>&1; then
        die "Homebrew not found. Install it from https://brew.sh/ then re-run ./install.sh"
      fi
      install_deps_brew
      ;;
    linux-unknown)
      die "Unsupported Linux distro. Supported: Ubuntu/Debian. Install python3-venv, pip, nmap, curl, gobuster/ffuf manually."
      ;;
    *)
      die "Unsupported OS. Supported: Ubuntu/Debian/macOS."
      ;;
  esac

  setup_venv
  install_oracle

  say ""
  say "[*] Install complete."
  say "    Activate: source .venv/bin/activate"
  say "    Doctor:   oracle --doctor"
  say "    Demo:     oracle --demo --web"
}

main "$@"

