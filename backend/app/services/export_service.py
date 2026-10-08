"""CSV and JSON export for scan results."""

from __future__ import annotations

import csv
import json
import os
from typing import Any

# Exported fields (vendor, hostname in particular) are sourced from the
# network itself - e.g. a device's DHCP hostname - and are untrusted. A
# cell value starting with one of these characters is interpreted as a
# formula by Excel/LibreOffice/Google Sheets when the CSV is opened,
# which can be used to run arbitrary formulas (including ones that call
# out to external resources) on whoever opens the export. This is the
# well-known "CSV injection"/"formula injection" class of bug. Prefixing
# the value with a single quote neutralises it while keeping the value
# readable - spreadsheet apps treat a leading apostrophe as "force text"
# and don't display it.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in _FORMULA_TRIGGER_CHARS:
        return "'" + value
    return value


def export_devices(
    devices: list[dict[str, Any]],
    path: str,
    fmt: str | None = None,
) -> None:
    """Write `devices` to a CSV or JSON file.

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network()/enrich_devices()
        /scan_devices_ports().
    path : str
        Where to write the file.
    fmt : str or None
        'csv' or 'json'. If None, inferred from `path`'s extension
        (.csv or .json).

    Raises
    ------
    ValueError
        If fmt is None and the extension isn't .csv or .json.
    OSError
        If the file can't be written.
    """
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            fmt = "csv"
        elif ext == ".json":
            fmt = "json"
        else:
            raise ValueError(
                f"cannot infer export format from {path!r} - pass "
                "fmt='csv'/'json' (or --format on the command line), "
                "or name the file .csv/.json"
            )

    if fmt == "csv":
        fieldnames = ["ip", "mac", "vendor", "hostname"]
        if any("role" in device for device in devices):
            fieldnames += ["open_ports", "role"]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for device in devices:
                row = dict(device)
                if isinstance(row.get("open_ports"), list):
                    row["open_ports"] = ";".join(str(port) for port in row["open_ports"])
                row = {key: _csv_safe(value) for key, value in row.items()}
                writer.writerow(row)
    elif fmt == "json":
        with open(path, "w") as f:
            json.dump(devices, f, indent=2)
    else:
        raise ValueError(f"unsupported export format {fmt!r} - use 'csv' or 'json'")
