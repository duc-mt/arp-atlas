"""
==============================================================================
Module Name:   test_validate_network.py
Description:   Source module test_validate_network.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_validate_network.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

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
