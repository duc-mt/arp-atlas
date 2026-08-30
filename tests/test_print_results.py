from __future__ import annotations

import main


class TestPrintResults:
    def test_prints_header_and_each_device(self, capsys):
        devices = [
            {"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"},
            {"ip": "192.168.1.2", "mac": "4a:7c:9f:3b:2d:8e"},
        ]
        main.print_results(devices)

        out = capsys.readouterr().out
        assert "IP Address" in out
        assert "MAC Address" in out
        assert "192.168.1.1" in out
        assert "9c:5a:6b:1e:4f:0c" in out
        assert "192.168.1.2" in out

    def test_prints_vendor_and_hostname_when_present(self, capsys):
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "b8:27:eb:11:22:33",
                "vendor": "Raspberry Pi Foundation",
                "hostname": "pi-hole.local",
            },
        ]
        main.print_results(devices)

        out = capsys.readouterr().out
        assert "Raspberry Pi Foundation" in out
        assert "pi-hole.local" in out

    def test_missing_vendor_or_hostname_prints_a_placeholder(self, capsys):
        """A plain, un-enriched device dict (e.g. straight from
        scan_network(), before enrich_devices() runs) must still print
        cleanly rather than raising a KeyError."""
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        main.print_results(devices)  # must not raise

        out = capsys.readouterr().out
        assert "192.168.1.1" in out

    def test_role_and_ports_columns_omitted_without_a_port_scan(self, capsys):
        devices = [{
            "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa",
            "vendor": None, "hostname": None,
        }]
        main.print_results(devices)

        out = capsys.readouterr().out
        assert "Role" not in out
        assert "Open Ports" not in out

    def test_role_and_ports_columns_shown_after_a_port_scan(self, capsys):
        devices = [{
            "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa",
            "vendor": None, "hostname": None,
            "open_ports": [22, 80], "role": "server",
        }]
        main.print_results(devices)

        out = capsys.readouterr().out
        assert "Role" in out
        assert "Open Ports" in out
        assert "22,80" in out
        assert "server" in out

    def test_no_open_ports_shows_a_placeholder_not_an_empty_cell(
        self, capsys
    ):
        devices = [{
            "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa",
            "vendor": None, "hostname": None,
            "open_ports": [], "role": "unknown",
        }]
        main.print_results(devices)

        out = capsys.readouterr().out
        assert "192.168.1.1\t\taa:aa:aa:aa:aa:aa\t\t-\t\t-\t\t-\t\tunknown" in out

    def test_empty_list_prints_a_friendly_message_not_a_bare_header(
        self, capsys
    ):
        """Regression test: previously an empty result set silently
        printed just the header row with no rows underneath, giving no
        clear indication that the scan found nothing."""
        main.print_results([])

        out = capsys.readouterr().out
        assert "No devices found" in out
        assert "IP Address" not in out
