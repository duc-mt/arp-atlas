"""
==============================================================================
Module Name:   test_lookup_vendor.py
Description:   Source module test_lookup_vendor.py.
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

from unittest import mock

from backend.app.services.enrichment import _load_manuf_db, _normalize_oui, lookup_vendor


class TestLookupVendor:
    def test_known_oui_returns_the_manufacturer_name(self):
        # b8:27:eb is a real, long-registered Raspberry Pi Foundation
        # OUI - stable enough to assert on directly.
        assert lookup_vendor("b8:27:eb:11:22:33") == ("Raspberry Pi Foundation")

    def test_unknown_oui_returns_none(self):
        # Made-up OUI, essentially guaranteed not to be registered.
        assert lookup_vendor("9c:5a:6b:1e:4f:0c") is None

    def test_is_case_insensitive(self):
        assert lookup_vendor("B8:27:EB:11:22:33") == ("Raspberry Pi Foundation")


class TestLookupVendorCustomManufDb:
    """Covers the OUI/vendor fix: `scapy.conf.manufdb` is only as fresh
    as the scapy release it ships with, so recently-allocated OUIs come
    back as a miss even though they're perfectly valid registrations.
    These exercise our own cached `manuf` database (see
    backend/app/data/manuf.gz), which is checked first.
    """

    def test_recently_allocated_oui_missing_from_scapy_is_resolved(self):
        # 10:5F:02 was allocated to Ruijie Networks in 2022 - long after
        # most scapy releases' bundled snapshot - so this is exactly the
        # kind of lookup that used to silently return None.
        assert lookup_vendor("10:5f:02:4b:88:aa") == "Ruijie Networks Co.,LTD"

    def test_custom_db_lookup_is_case_and_separator_insensitive(self):
        assert lookup_vendor("10-5F-02-AA-BB-CC") == "Ruijie Networks Co.,LTD"
        assert lookup_vendor("10:5f:02:aa:bb:cc") == "Ruijie Networks Co.,LTD"

    def test_custom_db_is_checked_before_the_scapy_fallback(self):
        # Even if scapy's bundled database somehow disagreed (e.g. an
        # OUI it mis-registered to another vendor), our own - more
        # current - cache should win, since it's checked first.
        with mock.patch("scapy.all.conf.manufdb._get_manuf", return_value="Stale Vendor Inc."):
            assert lookup_vendor("10:5f:02:00:00:01") == "Ruijie Networks Co.,LTD"

    def test_oui_not_in_either_database_still_falls_through_to_scapy(self):
        # Backward compatibility: an OUI our custom cache doesn't have
        # should still reach scapy's fallback exactly as before.
        assert lookup_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"

    def test_normalize_oui_accepts_several_input_shapes(self):
        assert _normalize_oui("10:5F:02:4B:88:AA") == "10:5F:02"
        assert _normalize_oui("10-5f-02-4b-88-aa") == "10:5F:02"
        assert _normalize_oui("105F024B88AA") == "10:5F:02"
        assert _normalize_oui("not-a-mac") is None
        assert _normalize_oui("ab:cd") is None

    def test_manuf_db_skips_cidr_masked_ranges(self):
        # Sanity check against the actual shipped file: the masked VRRP
        # entry included as a parser test fixture must never resolve as
        # if it were a plain /24 OUI.
        assert "00:00:5E" not in _load_manuf_db()
