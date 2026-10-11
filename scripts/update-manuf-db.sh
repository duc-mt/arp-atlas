#!/usr/bin/env bash
#
# Refresh backend/app/data/manuf.gz from Wireshark's official, continuously
# updated OUI database. Run this from CI, a cron job, or by hand whenever
# you want the vendor lookup to pick up newly-registered IEEE OUIs.
#
# Requires network access (this repo's own test/runtime code never makes
# one - only this maintenance script does).
#
# Usage:
#   scripts/update-manuf-db.sh
#
set -euo pipefail

SOURCE_URL="https://www.wireshark.org/download/automated/data/manuf"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${REPO_ROOT}/backend/app/data/manuf.gz"
TMP_RAW="$(mktemp)"

trap 'rm -f "${TMP_RAW}"' EXIT

echo "Downloading ${SOURCE_URL} ..."
curl --fail --silent --show-error --location "${SOURCE_URL}" -o "${TMP_RAW}"

if ! grep -q "Wireshark" "${TMP_RAW}"; then
    echo "error: downloaded file doesn't look like a Wireshark manuf file - aborting" >&2
    exit 1
fi

mkdir -p "$(dirname "${DEST}")"
gzip -c "${TMP_RAW}" > "${DEST}"

echo "Updated ${DEST} ($(wc -l < "${TMP_RAW}") lines, $(du -h "${DEST}" | cut -f1) compressed)."
echo "lookup_vendor() picks this up automatically on the next process start."
