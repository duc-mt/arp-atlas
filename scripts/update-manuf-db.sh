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
# Environment overrides (the defaults are what you want by hand; tests and
# CI use these to point the script somewhere else):
#   MANUF_SOURCE_URL   where to download from - any URL curl accepts, so a
#                      file:// URL works for offline runs
#   MANUF_DEST         where to write the gzip file
#   MANUF_MIN_ENTRIES  refuse a download with fewer OUI lines than this
#                      (default 1000; the real file has tens of thousands)
#
# The existing file is only replaced once the download has passed every
# check, and the output is deterministic (no timestamp or file name in the
# gzip header), so re-running on an unchanged database rewrites identical
# bytes.
set -euo pipefail

SOURCE_URL="${MANUF_SOURCE_URL:-https://www.wireshark.org/download/automated/data/manuf}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${MANUF_DEST:-${REPO_ROOT}/backend/app/data/manuf.gz}"
MIN_ENTRIES="${MANUF_MIN_ENTRIES:-1000}"

mkdir -p "$(dirname "${DEST}")"
TMP_RAW="$(mktemp)"
# Same directory as DEST, so the final mv is an atomic rename on one filesystem.
TMP_GZ="$(mktemp "${DEST}.XXXXXX")"

trap 'rm -f "${TMP_RAW}" "${TMP_GZ}"' EXIT

echo "Downloading ${SOURCE_URL} ..."
curl --fail --silent --show-error --location --retry 3 --retry-delay 5 \
    "${SOURCE_URL}" -o "${TMP_RAW}"

if ! grep -q "Wireshark" "${TMP_RAW}"; then
    echo "error: downloaded file doesn't look like a Wireshark manuf file - aborting" >&2
    exit 1
fi

# The header check above also passes an HTML error page that happens to name
# Wireshark, so require real OUI lines as well: "AA:BB:CC<tab>..." as well as the
# longer range form "AA:BB:CC:DD:EE:FF/36<tab>...".
ENTRIES="$(grep -Ec '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2,5}(/[0-9]{1,2})?[[:space:]]' "${TMP_RAW}" || true)"
if [ "${ENTRIES}" -lt "${MIN_ENTRIES}" ]; then
    echo "error: only ${ENTRIES} OUI entries found (expected at least ${MIN_ENTRIES}) - aborting" >&2
    exit 1
fi

gzip -n -c "${TMP_RAW}" > "${TMP_GZ}"
gzip -t "${TMP_GZ}"
chmod 644 "${TMP_GZ}"
mv -f "${TMP_GZ}" "${DEST}"

echo "Updated ${DEST} (${ENTRIES} OUI entries, $(du -h "${DEST}" | cut -f1) compressed)."
echo "lookup_vendor() picks this up automatically on the next process start."
