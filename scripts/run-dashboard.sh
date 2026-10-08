#!/usr/bin/env bash
# Launch the ARP Atlas web dashboard.
# Run with sudo because scapy needs raw socket access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

if [[ "$EUID" -ne 0 ]]; then
  echo "[!] This script requires root privileges to send ARP packets."
  echo "    Re-running with sudo..."
  exec sudo "$0" "$@"
fi

.venv/bin/python main.py --dashboard "$@"
