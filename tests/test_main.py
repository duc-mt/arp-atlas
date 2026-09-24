from __future__ import annotations

import typing
"""Tests for main.run_interactive(): the interactive session.

run_interactive() now prompts three times in the happy path: the
network, whether to scan ports, and an optional export path - so
input() is mocked with a side_effect list matching that order, rather
than a single fixed return_value.
"""


from unittest import mock

import main


class TestMainValidationError:
    def test_invalid_network_prints_error_and_does_not_scan(self, capsys):
        with mock.patch("builtins.input", return_value="not an address"), \
             mock.patch("main.scan_network") as mock_scan:
            main.run_interactive()

        mock_scan.assert_not_called()
        out = capsys.readouterr().out
        assert "not a valid network address" in out


class TestMainPermissionError:
    def test_permission_error_is_handled_gracefully(self, capsys):
        """Regression test: scanning without root privileges raises
        PermissionError from scapy.srp(), which used to be completely
        unhandled and would crash with a raw traceback."""
        with mock.patch("builtins.input", return_value="192.168.1.0/24"), \
             mock.patch(
                 "main.scan_network",
                 side_effect=PermissionError("Operation not permitted"),
             ):
            main.run_interactive()  # must not raise

        out = capsys.readouterr().out
        assert "Permission denied" in out


class TestMainHappyPath:
    def test_valid_network_scans_and_prints_results(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"}]
        inputs = iter([" 192.168.1.0/24 ", "n", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices) as mock_scan, \
             mock.patch("main.lookup_vendor", return_value="Some Vendor"), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"):
            main.run_interactive()

        mock_scan.assert_called_once_with("192.168.1.0/24")
        out = capsys.readouterr().out
        assert "192.168.1.1" in out
        assert "Some Vendor" in out

    def test_ip_conflict_prints_a_warning_before_the_results(self, capsys):
        """Two different MACs answering for the same IP - the
        find_ip_conflicts() case - should surface a warning."""
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"):
            main.run_interactive()

        out = capsys.readouterr().out
        assert "WARNING" in out
        assert "192.168.1.1" in out
        assert "aa:aa:aa:aa:aa:aa" in out
        assert "bb:bb:bb:bb:bb:bb" in out


class TestPortScanPrompt:
    def test_yes_answer_runs_the_port_scan(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "y", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.scan_devices_ports") as mock_scan_ports, \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"):
            main.run_interactive()

        mock_scan_ports.assert_called_once_with(devices)

    def test_default_no_answer_skips_the_port_scan(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.scan_devices_ports") as mock_scan_ports, \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"):
            main.run_interactive()

        mock_scan_ports.assert_not_called()


class TestHistoryDiff:
    def test_previous_scan_triggers_a_diff(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        previous = {
            "192.168.1.0/24": {
                "timestamp": "2024-01-01T00:00:00+00:00",
                "devices": [],
            },
        }
        inputs = iter(["192.168.1.0/24", "n", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value=previous), \
             mock.patch("main.save_scan") as mock_save_scan:
            main.run_interactive()

        out = capsys.readouterr().out
        assert "New devices since last scan" in out
        mock_save_scan.assert_called_once_with(
            main.HISTORY_FILE, "192.168.1.0/24", devices
        )

    def test_no_previous_scan_means_no_diff_output(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"):
            main.run_interactive()

        out = capsys.readouterr().out
        assert "since last scan" not in out


class TestExportPrompt:
    def test_blank_answer_skips_export(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", ""])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"), \
             mock.patch("main.export_devices") as mock_export:
            main.run_interactive()

        mock_export.assert_not_called()
        assert "exported" not in capsys.readouterr().out

    def test_a_path_triggers_export(self, capsys, tmp_path):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        out_path = str(tmp_path / "scan.csv")
        inputs = iter(["192.168.1.0/24", "n", out_path])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"), \
             mock.patch("main.export_devices") as mock_export:
            main.run_interactive()

        mock_export.assert_called_once_with(devices, out_path)
        assert "exported" in capsys.readouterr().out

    def test_export_failure_is_reported_not_raised(self, capsys):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        inputs = iter(["192.168.1.0/24", "n", "/no/such/dir/scan.csv"])
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None), \
             mock.patch("main.load_history", return_value={}), \
             mock.patch("main.save_scan"), \
             mock.patch(
                 "main.export_devices",
                 side_effect=OSError("No such file or directory"),
             ):
            main.run_interactive()  # must not raise

        assert "Could not export results" in capsys.readouterr().out
