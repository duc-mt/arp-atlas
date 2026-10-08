from __future__ import annotations

from unittest import mock

import main


class TestMainValidationError:
    def test_invalid_network_prints_error_and_does_not_scan(self, capsys):
        with mock.patch("builtins.input", return_value="not an address"), \
             mock.patch("main.scan_network") as mock_scan:
            main.main()

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
            main.main()  # must not raise

        out = capsys.readouterr().out
        assert "Permission denied" in out


class TestMainHappyPath:
    def test_valid_network_scans_and_prints_results(self, capsys):
        devices = [{"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"}]
        with mock.patch("builtins.input", return_value=" 192.168.1.0/24 "), \
             mock.patch("main.scan_network", return_value=devices) as mock_scan, \
             mock.patch("main.lookup_vendor", return_value="Some Vendor"), \
             mock.patch("main.lookup_hostname", return_value=None):
            main.main()

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
        with mock.patch("builtins.input", return_value="192.168.1.0/24"), \
             mock.patch("main.scan_network", return_value=devices), \
             mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main.lookup_hostname", return_value=None):
            main.main()

        out = capsys.readouterr().out
        assert "WARNING" in out
        assert "192.168.1.1" in out
        assert "aa:aa:aa:aa:aa:aa" in out
        assert "bb:bb:bb:bb:bb:bb" in out
