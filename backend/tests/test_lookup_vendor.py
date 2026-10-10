"""
==============================================================================
Module Name:   test_lookup_vendor.py
Description:   Implementation and logic for test_lookup_vendor.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_lookup_vendor.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""
from __future__ import annotations

"""Tests for lookup_vendor().

Uses scapy's own bundled IEEE manufacturer database, so these are
offline and deterministic - no network call, no new dependency.
"""


from backend.app.services.enrichment import lookup_vendor


class TestLookupVendor:
    def test_known_oui_returns_the_manufacturer_name(self):
        # b8:27:eb is a real, long-registered Raspberry Pi Foundation
        # OUI - stable enough to assert on directly.
        assert lookup_vendor("b8:27:eb:11:22:33") == (
            "Raspberry Pi Foundation"
        )

    def test_unknown_oui_returns_none(self):
        # Made-up OUI, essentially guaranteed not to be registered.
        assert lookup_vendor("9c:5a:6b:1e:4f:0c") is None

    def test_is_case_insensitive(self):
        assert lookup_vendor("B8:27:EB:11:22:33") == (
            "Raspberry Pi Foundation"
        )
