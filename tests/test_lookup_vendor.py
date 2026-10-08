from __future__ import annotations

import typing
"""Tests for main.lookup_vendor().

Uses scapy's own bundled IEEE manufacturer database, so these are
offline and deterministic - no network call, no new dependency.
"""


import main


class TestLookupVendor:
    def test_known_oui_returns_the_manufacturer_name(self):
        # b8:27:eb is a real, long-registered Raspberry Pi Foundation
        # OUI - stable enough to assert on directly.
        assert main.lookup_vendor("b8:27:eb:11:22:33") == (
            "Raspberry Pi Foundation"
        )

    def test_unknown_oui_returns_none(self):
        # Made-up OUI, essentially guaranteed not to be registered.
        assert main.lookup_vendor("9c:5a:6b:1e:4f:0c") is None

    def test_is_case_insensitive(self):
        assert main.lookup_vendor("B8:27:EB:11:22:33") == (
            "Raspberry Pi Foundation"
        )
