"""Tests for main.validate_network().

Regression coverage for two bugs found during review:

1. The original code fed the raw, un-stripped user input straight into
   ipaddress.ip_network(), so a pasted address with a trailing newline
   or leading space - a very common paste artifact - was rejected as
   invalid even though it's a perfectly valid address once trimmed.
2. ip_network() defaults to strict=True, which rejects any address
   with host bits set relative to its prefix - e.g. "192.168.1.5/24",
   a natural way to type "scan the subnet this host is on" - even
   though the intent is unambiguous and scapy's own address expansion
   already normalises it down to the containing network correctly.
"""

from __future__ import annotations

import pytest

import main


class TestAcceptsValidAddresses:
    def test_bare_network_address(self):
        assert main.validate_network("192.168.1.0/24") == "192.168.1.0/24"

    def test_single_host_without_prefix(self):
        assert main.validate_network("192.168.1.5") == "192.168.1.5"


class TestStripsWhitespace:
    def test_leading_space(self):
        assert main.validate_network(" 192.168.1.0/24") == "192.168.1.0/24"

    def test_trailing_space(self):
        assert main.validate_network("192.168.1.0/24 ") == "192.168.1.0/24"

    def test_trailing_newline(self):
        assert main.validate_network("192.168.1.0/24\n") == "192.168.1.0/24"


class TestAcceptsHostAddressWithPrefix:
    def test_host_bits_set_is_no_longer_rejected(self):
        # Previously raised ValueError("... has host bits set").
        result = main.validate_network("192.168.1.5/24")
        assert result == "192.168.1.5/24"


class TestRejectsInvalidInput:
    def test_garbage_string(self):
        with pytest.raises(ValueError):
            main.validate_network("not an address")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            main.validate_network("")

    def test_whitespace_only(self):
        with pytest.raises(ValueError):
            main.validate_network("   ")

    def test_out_of_range_octet(self):
        with pytest.raises(ValueError):
            main.validate_network("999.168.1.0/24")
