#!/usr/bin/env bash
# ==============================================================================
# Script Name:   run.sh
# Description:   Cross-platform shell launcher for ARP Atlas
# Usage:         ./run.sh [options]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for raw socket / root privileges on Unix-like systems and elevate via sudo
if [ "$(uname -s)" != "MINGW"* ] && [ "$(uname -s)" != "CYGWIN"* ]; then
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "[!] ARP Atlas requires root privileges (sudo) to send raw ARP packets."
        echo "    Re-running with sudo..."
        exec sudo "$0" "$@"
    fi
fi

# 1. If virtual environment exists, use its Python directly
if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python run.py "$@"
fi

# 2. Prefer modern Python versions (3.13, 3.12, 3.11, 3.10) before default python3/python
CANDIDATES=("python3.13" "python3.12" "python3.11" "python3.10" "python3" "python")

for py in "${CANDIDATES[@]}"; do
    if command -v "$py" >/dev/null 2>&1; then
        if "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            exec "$py" run.py "$@"
        fi
    fi
done

echo "[ERROR] Python 3.10+ is required but not found in PATH." >&2
echo "Please install Python 3.10+ (https://www.python.org/) or install via Homebrew / package manager." >&2
exit 1
