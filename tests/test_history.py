from __future__ import annotations

import main


class TestLoadHistory:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        path = str(tmp_path / "scan_history.json")
        assert main.load_history(path) == {}

    def test_corrupt_file_returns_empty_dict(self, tmp_path):
        path = tmp_path / "scan_history.json"
        path.write_text("not valid json{{{")
        assert main.load_history(str(path)) == {}

    def test_reads_back_what_was_saved(self, tmp_path):
        path = str(tmp_path / "scan_history.json")
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        main.save_scan(path, "192.168.1.0/24", devices)

        history = main.load_history(path)
        assert history["192.168.1.0/24"]["devices"] == devices


class TestSaveScan:
    def test_includes_a_timestamp(self, tmp_path):
        path = str(tmp_path / "scan_history.json")
        main.save_scan(path, "192.168.1.0/24", [])

        history = main.load_history(path)
        assert "timestamp" in history["192.168.1.0/24"]

    def test_saving_a_different_network_preserves_the_first(self, tmp_path):
        path = str(tmp_path / "scan_history.json")
        main.save_scan(path, "192.168.1.0/24", [{"ip": "1", "mac": "a"}])
        main.save_scan(path, "10.0.0.0/24", [{"ip": "2", "mac": "b"}])

        history = main.load_history(path)
        assert history["192.168.1.0/24"]["devices"] == [
            {"ip": "1", "mac": "a"}
        ]
        assert history["10.0.0.0/24"]["devices"] == [{"ip": "2", "mac": "b"}]

    def test_saving_the_same_network_again_replaces_its_entry(
        self, tmp_path
    ):
        path = str(tmp_path / "scan_history.json")
        main.save_scan(path, "192.168.1.0/24", [{"ip": "1", "mac": "a"}])
        main.save_scan(path, "192.168.1.0/24", [{"ip": "2", "mac": "b"}])

        history = main.load_history(path)
        assert history["192.168.1.0/24"]["devices"] == [
            {"ip": "2", "mac": "b"}
        ]


class TestDiffDevices:
    def test_no_changes_produces_empty_diff(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        diff = main.diff_devices(devices, devices)
        assert diff == {"new": [], "missing": [], "ip_changed": []}

    def test_a_new_mac_is_reported_as_new(self):
        previous = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        current = [
            *previous,
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]

        diff = main.diff_devices(previous, current)

        assert [d["mac"] for d in diff["new"]] == ["bb:bb:bb:bb:bb:bb"]
        assert diff["missing"] == []
        assert diff["ip_changed"] == []

    def test_a_disappeared_mac_is_reported_as_missing(self):
        previous = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        current = [previous[0]]

        diff = main.diff_devices(previous, current)

        assert [d["mac"] for d in diff["missing"]] == ["bb:bb:bb:bb:bb:bb"]
        assert diff["new"] == []

    def test_same_mac_different_ip_is_reported_as_ip_changed_not_new_or_missing(
        self,
    ):
        """The key behaviour: identity is tracked by MAC, not IP,
        since IP can change under DHCP between scans - so this must
        NOT show up as one device vanishing and a different one
        appearing."""
        previous = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        current = [{"ip": "192.168.1.99", "mac": "aa:aa:aa:aa:aa:aa"}]

        diff = main.diff_devices(previous, current)

        assert diff["new"] == []
        assert diff["missing"] == []
        assert len(diff["ip_changed"]) == 1
        changed_device, old_ip = diff["ip_changed"][0]
        assert changed_device["ip"] == "192.168.1.99"
        assert old_ip == "192.168.1.1"

    def test_empty_previous_scan_marks_everything_as_new(self):
        current = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        diff = main.diff_devices([], current)
        assert diff["new"] == current


class TestPrintDiff:
    def test_prints_nothing_extra_for_an_empty_diff(self, capsys):
        main.print_diff({"new": [], "missing": [], "ip_changed": []})
        assert capsys.readouterr().out == ""

    def test_prints_new_devices(self, capsys):
        diff = {
            "new": [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}],
            "missing": [], "ip_changed": [],
        }
        main.print_diff(diff)
        out = capsys.readouterr().out
        assert "New devices" in out
        assert "192.168.1.1" in out

    def test_prints_missing_devices(self, capsys):
        diff = {
            "new": [],
            "missing": [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}],
            "ip_changed": [],
        }
        main.print_diff(diff)
        out = capsys.readouterr().out
        assert "missing" in out
        assert "192.168.1.1" in out

    def test_prints_ip_changes_with_before_and_after(self, capsys):
        diff = {
            "new": [], "missing": [],
            "ip_changed": [
                ({"ip": "192.168.1.99", "mac": "aa:aa:aa:aa:aa:aa"},
                 "192.168.1.1"),
            ],
        }
        main.print_diff(diff)
        out = capsys.readouterr().out
        assert "192.168.1.1" in out
        assert "192.168.1.99" in out
