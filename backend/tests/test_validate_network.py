from __future__ import annotations

"""
==============================================================================
Module Name:   test_validate_network.py
Description:   Implementation and logic for test_validate_network.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_validate_network.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

"""Tests for validate_network().

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

import pytest

from backend.app.scanner.arp_scanner import validate_network


class TestValidateNetwork:
    @pytest.mark.parametrize(
        "input_network, expected",
        [
            ("192.168.1.0/24", "192.168.1.0/24"),
            ("192.168.1.5", "192.168.1.5/32"),
            (" 192.168.1.0/24", "192.168.1.0/24"),
            ("192.168.1.0/24 ", "192.168.1.0/24"),
            ("192.168.1.0/24\n", "192.168.1.0/24"),
            ("192.168.1.5/24", "192.168.1.0/24"),
        ],
        ids=[
            "bare_network",
            "single_host",
            "leading_space",
            "trailing_space",
            "trailing_newline",
            "host_bits_set_normalized",
        ],
    )
    def test_valid_inputs(self, input_network: str, expected: str) -> None:
        """Test that valid network addresses (and those with common formatting issues) are accepted and normalized."""
        assert validate_network(input_network) == expected

    @pytest.mark.parametrize(
        "invalid_network",
        [
            "not an address",
            "",
            "   ",
            "999.168.1.0/24",
        ],
        ids=[
            "garbage_string",
            "empty_string",
            "whitespace_only",
            "out_of_range_octet",
        ],
    )
    def test_invalid_inputs(self, invalid_network: str) -> None:
        """Test that garbage strings, empty inputs, or out-of-range IPs correctly raise ValueErrors."""
        with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 network"):
            validate_network(invalid_network)
