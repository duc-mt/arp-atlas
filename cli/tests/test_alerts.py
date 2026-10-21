"""
==============================================================================
Module Name:   test_alerts.py
Description:   Tests for the watch-mode alert printer.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest cli/tests/test_alerts.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import pytest

from backend.app.services.watch_service import (
    GATEWAY_MAC_CHANGED,
    MAC_CHANGED,
    NEW_DEVICE,
    Alert,
)
from cli.arp_atlas_cli.formatters import print_alerts


def test_nothing_to_print_prints_nothing(capsys: pytest.CaptureFixture) -> None:
    print_alerts([])
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("kind", "label"),
    [
        (NEW_DEVICE, "NEW DEVICE"),
        (MAC_CHANGED, "MAC CHANGED"),
        (GATEWAY_MAC_CHANGED, "GATEWAY MAC CHANGED"),
    ],
)
def test_each_kind_has_a_readable_label(
    kind: str, label: str, capsys: pytest.CaptureFixture
) -> None:
    print_alerts([Alert(kind, "192.168.1.9", "aa:bb:cc:dd:ee:ff", "detail")])
    out = capsys.readouterr().out

    assert f"[!] {label}: 192.168.1.9" in out
    assert "aa:bb:cc:dd:ee:ff" in out


def test_every_alert_is_printed(capsys: pytest.CaptureFixture) -> None:
    print_alerts(
        [
            Alert(NEW_DEVICE, "192.168.1.9", "aa:bb:cc:dd:ee:01", "x"),
            Alert(NEW_DEVICE, "192.168.1.10", "aa:bb:cc:dd:ee:02", "y"),
        ]
    )
    assert capsys.readouterr().out.count("[!]") == 2


def test_an_unknown_kind_is_still_shown(capsys: pytest.CaptureFixture) -> None:
    print_alerts([Alert("something_new", "192.168.1.9", "aa:bb:cc:dd:ee:ff", "detail")])
    assert "SOMETHING_NEW" in capsys.readouterr().out
