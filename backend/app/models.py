"""
==============================================================================
Module Name:   models.py
Description:   Typed view over the plain device dicts the scan pipeline passes
               around, with an exact dict round trip.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         from backend.app.models import NetworkDevice
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import dataclasses
from typing import Any

# Keys a pipeline stage adds after `scan_network()` has produced ip/mac.
_STAGE_KEYS = ("vendor", "hostname", "is_randomized", "open_ports", "role")


@dataclasses.dataclass
class NetworkDevice:
    """One scanned device, as a typed object.

    The pipeline (`scan_network()` -> `enrich_devices()` ->
    `scan_devices_ports()`) still passes plain dicts, and
    `export_devices()` / history persistence depend on exactly which keys
    those dicts carry - e.g. the CSV only gains `open_ports`/`role`
    columns once a device has a `role`. This class therefore round-trips
    exactly: `NetworkDevice.from_dict(d).to_dict() == d`, including which
    keys are present, so adopting it can't change an export or a history
    file by accident.

    The stage fields (`vendor`, `hostname`, `is_randomized`, `open_ports`,
    `role`) are None until their stage has run. `to_dict()` leaves a
    None stage field out, unless the source dict carried it explicitly
    (`vendor` and `hostname` are legitimately null after enrichment when
    nothing resolved).

    Any other keys (a newer version's fields, say) are kept in `extra`
    and written back out, never silently dropped.
    """

    ip: str
    mac: str
    vendor: str | None = None
    hostname: str | None = None
    is_randomized: bool | None = None
    open_ports: list[int] | None = None
    role: str | None = None
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)
    _present: frozenset[str] = dataclasses.field(
        default=frozenset(), init=False, repr=False, compare=False
    )

    def to_dict(self) -> dict[str, Any]:
        """The plain-dict form the rest of the pipeline expects."""
        data: dict[str, Any] = {"ip": self.ip, "mac": self.mac}
        for key in _STAGE_KEYS:
            value = getattr(self, key)
            if value is not None or key in self._present:
                data[key] = list(value) if isinstance(value, list) else value
        data.update(self.extra)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkDevice:
        """Build from a pipeline/history dict. Needs `ip` and `mac`."""
        known = {"ip", "mac", *_STAGE_KEYS}
        open_ports = data.get("open_ports")
        device = cls(
            ip=data["ip"],
            mac=data["mac"],
            vendor=data.get("vendor"),
            hostname=data.get("hostname"),
            is_randomized=data.get("is_randomized"),
            open_ports=list(open_ports) if open_ports is not None else None,
            role=data.get("role"),
            extra={k: v for k, v in data.items() if k not in known},
        )
        device._present = frozenset(k for k in _STAGE_KEYS if k in data)
        return device
