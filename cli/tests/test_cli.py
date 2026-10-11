"""
==============================================================================
Module Name:   test_cli.py
Description:   Source module test_cli.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_cli.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import typing
from pathlib import Path

"""Tests for the non-interactive CLI mode.

Exercises cli.arp_atlas_cli.main.main() with a mocked sys.argv, which is how a
person would actually invoke `python main.py --network ...` from a shell.
"""

from unittest import mock

import pytest

from backend.app.config import DEFAULT_TIMEOUT, HISTORY_FILE
from cli.arp_atlas_cli.main import main


def run_main(argv: list[str]) -> int:
    with (
        mock.patch("sys.argv", ["arp-atlas", *argv]),
        mock.patch("cli.arp_atlas_cli.main.check_privileges"),
    ):
        return main()


# The module where the functions are *looked up* during CLI execution
_M = "cli.arp_atlas_cli.main"


class TestNoNetworkRunsInteractive:
    def test_no_arguments_runs_the_interactive_prompt(self) -> None:
        with mock.patch(f"{_M}.run_interactive", return_value=0) as mock_run:
            exit_code = run_main([])
        mock_run.assert_called_once()
        assert exit_code == 0


class TestNetworkRunsCli:
    def test_invalid_network_is_an_error(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            run_main(["--network", "not an address"])
        assert exc_info.value.code == 2

    def test_valid_network_scans_and_prints(self, capsys: pytest.CaptureFixture) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            exit_code = run_main(["--network", "192.168.1.0/24"])

        assert exit_code == 0
        assert "192.168.1.1" in capsys.readouterr().out

    def test_permission_error_is_handled_gracefully(self, capsys: pytest.CaptureFixture) -> None:
        with mock.patch(
            f"{_M}.scan_network",
            side_effect=PermissionError("Operation not permitted"),
        ):
            exit_code = run_main(["--network", "192.168.1.0/24"])

        assert exit_code == 1
        assert "Permission denied" in capsys.readouterr().out

    def test_ip_conflict_prints_a_warning(self, capsys: pytest.CaptureFixture) -> None:
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert "WARNING" in capsys.readouterr().out


class TestTimeoutFlag:
    def test_default_timeout_is_used_when_not_given(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_scan.assert_called_once_with("192.168.1.0/24", timeout=DEFAULT_TIMEOUT, gentle=False)

    def test_custom_timeout_is_passed_through(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--timeout", "3.5"])

        mock_scan.assert_called_once_with("192.168.1.0/24", timeout=3.5, gentle=False)


class TestGentleScanFlag:
    def test_not_enabled_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert mock_scan.call_args.kwargs["gentle"] is False

    def test_enabled_by_flag(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--gentle-scan"])

        assert mock_scan.call_args.kwargs["gentle"] is True


class TestScanPortsFlag:
    def test_not_run_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_scan_ports.assert_not_called()

    def test_run_when_flag_given(self) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--scan-ports"])

        mock_scan_ports.assert_called_once_with(devices, method="connect")

    def test_syn_scan_flag_selects_the_syn_method(self) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--scan-ports", "--syn-scan"])

        mock_scan_ports.assert_called_once_with(devices, method="syn")

    def test_syn_scan_flag_without_scan_ports_does_nothing(self) -> None:
        """--syn-scan only matters alongside --scan-ports; on its own it
        shouldn't make scan_devices_ports run."""
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--syn-scan"])

        mock_scan_ports.assert_not_called()


class TestHistoryFlags:
    def test_diff_and_save_run_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}) as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_load.assert_called_once_with(HISTORY_FILE)
        mock_save.assert_called_once_with(HISTORY_FILE, "192.168.1.0/24", [])

    def test_no_history_flag_skips_both(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history") as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(["--network", "192.168.1.0/24", "--no-history"])

        mock_load.assert_not_called()
        mock_save.assert_not_called()

    def test_custom_history_file_is_used(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}) as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--history-file",
                    "custom.json",
                ]
            )

        mock_load.assert_called_once_with("custom.json")
        mock_save.assert_called_once_with("custom.json", "192.168.1.0/24", [])

    def test_diff_is_printed_when_a_previous_scan_exists(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        previous = {
            "192.168.1.0/24": {"timestamp": "x", "devices": []},
        }
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value=previous),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert "New devices since last scan" in capsys.readouterr().out


class TestOutputFlag:
    def test_exports_to_the_given_path(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.csv")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--output", out_path])

        assert (tmp_path / "scan.csv").exists()

    def test_format_flag_overrides_extension_inference(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.dat")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            exit_code = run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--output",
                    out_path,
                    "--format",
                    "json",
                ]
            )

        assert exit_code == 0
        content = (tmp_path / "scan.dat").read_text()
        assert content.strip().startswith("[")  # valid JSON array

    def test_unrecognised_extension_without_format_is_an_error(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.txt")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_main(["--network", "192.168.1.0/24", "--output", out_path])

        assert exc_info.value.code == 2


class TestCheckPrivileges:
    def test_windows_skips_privilege_check(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with mock.patch("sys.platform", "win32"):
            # Should not raise SystemExit
            check_privileges()

    def test_root_user_passes(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=0),
        ):
            check_privileges()

    def test_non_root_without_raw_socket_fails(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("socket.socket", side_effect=PermissionError("Permission denied")),
            pytest.raises(SystemExit) as exc_info,
        ):
            check_privileges()
        assert exc_info.value.code == 1

    def test_non_root_with_raw_socket_passes(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        mock_sock = mock.MagicMock()
        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("socket.socket", return_value=mock_sock),
        ):
            check_privileges()
        mock_sock.close.assert_called_once()
