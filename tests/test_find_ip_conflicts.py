from __future__ import annotations

"""Tests for main.find_ip_conflicts().

Two different MACs both answering for the same IP in one scan is the
classic signature of a misconfigured static IP or ARP spoofing.
"""


import main


class TestFindIpConflicts:
    def test_no_conflicts_returns_empty_dict(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        assert main.find_ip_conflicts(devices) == {}

    def test_same_ip_different_macs_is_flagged(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        assert main.find_ip_conflicts(devices) == {
            "192.168.1.1": ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"],
        }

    def test_same_ip_same_mac_twice_is_not_flagged(self):
        """A duplicate answer from the same device isn't a conflict -
        only genuinely different MACs claiming the same IP are."""
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
        ]
        assert main.find_ip_conflicts(devices) == {}

    def test_empty_device_list(self):
        assert main.find_ip_conflicts([]) == {}

    def test_three_way_conflict_lists_all_macs_sorted(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "cc:cc:cc:cc:cc:cc"},
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        assert main.find_ip_conflicts(devices) == {
            "192.168.1.1": [
                "aa:aa:aa:aa:aa:aa",
                "bb:bb:bb:bb:bb:bb",
                "cc:cc:cc:cc:cc:cc",
            ],
        }
