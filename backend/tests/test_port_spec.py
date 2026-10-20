"""
==============================================================================
Module Name:   test_port_spec.py
Description:   Tests for parse_port_spec() and for the default port list
               actually covering what classify_device() looks for.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_port_spec.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import pytest

from backend.app.config import COMMON_PORTS, PORT_PRESETS, QUICK_PORTS, SNMP_PORT
from backend.app.scanner.classifier import classify_device, parse_port_spec


class TestParsePortSpec:
    def test_common_preset(self) -> None:
        assert parse_port_spec("common") == COMMON_PORTS

    def test_quick_preset_is_the_original_five_ports(self) -> None:
        assert parse_port_spec("quick") == [22, 80, 443, 3389, 9100]

    def test_preset_name_is_case_insensitive_and_trimmed(self) -> None:
        assert parse_port_spec("  Quick ") == QUICK_PORTS

    def test_preset_result_is_a_copy(self) -> None:
        ports = parse_port_spec("quick")
        ports.append(1)
        assert QUICK_PORTS[-1] != 1
        assert PORT_PRESETS["quick"] == [22, 80, 443, 3389, 9100]

    def test_single_port(self) -> None:
        assert parse_port_spec("8080") == [8080]

    def test_list_keeps_the_order_given(self) -> None:
        assert parse_port_spec("443,22,80") == [443, 22, 80]

    def test_whitespace_around_entries_is_ignored(self) -> None:
        assert parse_port_spec(" 22 , 80 ") == [22, 80]

    def test_range_is_inclusive(self) -> None:
        assert parse_port_spec("8000-8003") == [8000, 8001, 8002, 8003]

    def test_list_and_range_mix(self) -> None:
        assert parse_port_spec("22,8000-8002,443") == [22, 8000, 8001, 8002, 443]

    def test_duplicates_are_dropped_keeping_the_first(self) -> None:
        assert parse_port_spec("80,22,80,20-22") == [80, 22, 20, 21]

    def test_boundary_ports_are_accepted(self) -> None:
        assert parse_port_spec("1,65535") == [1, 65535]

    @pytest.mark.parametrize(
        "spec",
        ["", "22,,80", "22,", "abc", "22,abc", "0", "65536", "-80", "80-", "80-70", "1.5"],
    )
    def test_invalid_specs_raise_value_error(self, spec: str) -> None:
        with pytest.raises(ValueError):
            parse_port_spec(spec)

    def test_error_message_names_the_offending_value(self) -> None:
        with pytest.raises(ValueError, match="'abc'"):
            parse_port_spec("22,abc")

    def test_out_of_range_error_message(self) -> None:
        with pytest.raises(ValueError, match="65536"):
            parse_port_spec("65536")


class TestDefaultPortsCoverTheClassifier:
    """COMMON_PORTS used to be five ports, so most of classify_device()'s
    signatures could never fire. For every role it can return, this
    checks that some combination of *default* ports reaches it."""

    @pytest.mark.parametrize(
        ("role", "vendor", "ports"),
        [
            ("ip camera", None, [554]),
            ("ip camera", None, [8000]),
            ("ip camera", None, [37777]),
            ("ip camera", None, [34567]),
            ("smart home device", None, [1883]),
            ("smart home device", None, [8883]),
            ("printer", None, [9100]),
            ("printer", None, [515]),
            ("printer", None, [631]),
            ("windows host", None, [135, 445]),
            ("windows host", None, [3389]),
            ("server", None, [22, 3306]),
            ("server", None, [21, 25]),
            ("router/switch", "Cisco Systems", [23]),
            ("web-enabled device", None, [8080]),
            ("web-enabled device", None, [8443]),
        ],
    )
    def test_role_is_reachable_with_default_ports(
        self, role: str, vendor: str | None, ports: list[int]
    ) -> None:
        assert set(ports) <= set(COMMON_PORTS)
        assert classify_device(vendor, ports) == role

    def test_default_list_has_no_duplicates_and_valid_ports(self) -> None:
        assert len(COMMON_PORTS) == len(set(COMMON_PORTS))
        assert all(1 <= port <= 65535 for port in COMMON_PORTS)

    def test_snmp_is_not_in_the_tcp_list(self) -> None:
        """161 is UDP - a TCP probe of it could never succeed, which is
        what made classify_device()'s 161 rule dead code."""
        assert SNMP_PORT == 161
        assert SNMP_PORT not in COMMON_PORTS
