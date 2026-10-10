from __future__ import annotations

"""
==============================================================================
Module Name:   test_main.py
Description:   Implementation and logic for test_main.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_main.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

import typing

"""Tests for run_interactive(): the interactive session.

run_interactive() prompts three times in the happy path: the
network, whether to scan ports, and an optional export path.
"""

from unittest import mock

from backend.app.config import HISTORY_FILE
from cli.arp_atlas_cli.main import run_interactive

# Module where functions are looked up during run_interactive execution
_M = "cli.arp_atlas_cli.main"


class TestMainValidationError:
    def test_invalid_network_prints_error_and_does_not_scan(self, capsys: mock.ANY) -> None:
        with (
            mock.patch("builtins.input", return_value="not an address"),
            mock.patch(f"{_M}.scan_network") as mock_scan,
        ):
            run_interactive()

        mock_scan.assert_not_called()
        out = capsys.readouterr().out
        assert "not a valid network address" in out


class TestMainPermissionError:
    def test_permission_error_is_handled_gracefully(self, capsys: mock.ANY) -> None:
        with (
            mock.patch("builtins.input", return_value="192.168.1.0/24"),
            mock.patch(
                f"{_M}.scan_network",
                side_effect=PermissionError("Operation not permitted"),
            ),
        ):
            run_interactive()  # must not raise

        out = capsys.readouterr().out
        assert "Permission denied" in out


class TestMainHappyPath:
    def test_valid_network_scans_and_prints_results(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"}]
        inputs = iter([" 192.168.1.0/24 ", "n", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices) as mock_scan,
            mock.patch(
                f"{_M}.enrich_devices",
                side_effect=lambda devs: (
                    devs.__setitem__(
                        0,
                        {
                            **devs[0],
                            "vendor": "Some Vendor",
                            "hostname": None,
                            "is_randomized": False,
                        },
                    )
                    or devs
                ),
            ),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_interactive()

        mock_scan.assert_called_once_with("192.168.1.0/24")
        out = capsys.readouterr().out
        assert "192.168.1.1" in out

    def test_ip_conflict_prints_a_warning_before_the_results(self, capsys: mock.ANY) -> None:
        """Two different MACs answering for the same IP should surface a warning."""
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_interactive()

        out = capsys.readouterr().out
        assert "WARNING" in out
        assert "192.168.1.1" in out
        assert "aa:aa:aa:aa:aa:aa" in out
        assert "bb:bb:bb:bb:bb:bb" in out


class TestPortScanPrompt:
    def test_yes_answer_runs_the_port_scan(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "y", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_interactive()

        mock_scan_ports.assert_called_once_with(devices)

    def test_default_no_answer_skips_the_port_scan(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_interactive()

        mock_scan_ports.assert_not_called()


class TestHistoryDiff:
    def test_previous_scan_triggers_a_diff(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        previous = {
            "192.168.1.0/24": {
                "timestamp": "2024-01-01T00:00:00+00:00",
                "devices": [],
            },
        }
        inputs = iter(["192.168.1.0/24", "n", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value=previous),
            mock.patch(f"{_M}.save_scan") as mock_save_scan,
        ):
            run_interactive()

        out = capsys.readouterr().out
        assert "New devices since last scan" in out
        mock_save_scan.assert_called_once_with(HISTORY_FILE, "192.168.1.0/24", devices)

    def test_no_previous_scan_means_no_diff_output(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_interactive()

        out = capsys.readouterr().out
        assert "since last scan" not in out


class TestExportPrompt:
    def test_blank_answer_skips_export(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.export_devices") as mock_export,
        ):
            run_interactive()

        mock_export.assert_not_called()
        assert "exported" not in capsys.readouterr().out

    def test_a_path_triggers_export(self, capsys: mock.ANY, tmp_path: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        out_path = str(tmp_path / "scan.csv")
        inputs = iter(["192.168.1.0/24", "n", out_path])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.export_devices") as mock_export,
        ):
            run_interactive()

        mock_export.assert_called_once_with(devices, out_path)
        assert "exported" in capsys.readouterr().out

    def test_export_failure_is_reported_not_raised(self, capsys: mock.ANY) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", "/no/such/dir/scan.csv"])
        with (
            mock.patch("builtins.input", lambda *a: next(inputs)),
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(
                f"{_M}.export_devices",
                side_effect=OSError("No such file or directory"),
            ),
        ):
            run_interactive()  # must not raise

        assert "Could not export results" in capsys.readouterr().out
