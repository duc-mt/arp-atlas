"""CSV and JSON export for scan results."""

from __future__ import annotations

import csv
import json
import os
from typing import Any


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
                writer.writerow(row)
    else:  # json
        with open(path, "w") as f:
            json.dump(devices, f, indent=2)
