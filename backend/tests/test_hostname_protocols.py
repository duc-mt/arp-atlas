"""
==============================================================================
Module Name:   test_hostname_protocols.py
Description:   Source module test_hostname_protocols.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-11
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_hostname_protocols.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import struct

from backend.app.services.enrichment import (
    _build_dns_ptr_query,
    _build_nbns_query,
    _encode_netbios_name,
    _NBNS_WILDCARD_NAME,
    _parse_nbns_response,
    _parse_ptr_response,
    _reverse_name,
)


def _fake_ptr_response(transaction_id: int, question_name: str, ptr_target: str) -> bytes:
    """Build a byte-for-byte realistic mDNS/LLMNR-style PTR response:
    header + echoed question + one answer (using a compression pointer
    back to the question, the way real resolvers do)."""
    header = struct.pack(">HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
    question = b""
    for label in question_name.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + struct.pack(">HH", 12, 1)

    rdata = b""
    for label in ptr_target.split("."):
        rdata += bytes([len(label)]) + label.encode("ascii")
    rdata += b"\x00"

    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    return header + question + answer


class TestReverseName:
    def test_builds_in_addr_arpa_name(self):
        assert _reverse_name("192.168.1.50") == "50.1.168.192.in-addr.arpa"

    def test_handles_simple_addresses(self):
        assert _reverse_name("10.0.0.1") == "1.0.0.10.in-addr.arpa"


class TestDnsPtrQuery:
    def test_query_contains_transaction_id_and_is_a_ptr_question(self):
        query = _build_dns_ptr_query("1.1.168.192.in-addr.arpa", 0x55AA)
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", query[0:12])
        assert tid == 0x55AA
        assert (flags, qdcount, ancount, nscount, arcount) == (0, 1, 0, 0, 0)
        # Last 4 bytes of the question are QTYPE=PTR(12), QCLASS=IN(1).
        assert struct.unpack(">HH", query[-4:]) == (12, 1)

    def test_encodes_labels_with_length_prefixes(self):
        query = _build_dns_ptr_query("50.1.168.192.in-addr.arpa", 1)
        # First label after the 12-byte header is "50" -> length-prefixed.
        assert query[12] == len("50")
        assert query[13 : 13 + len("50")] == b"50"


class TestParsePtrResponse:
    def test_decodes_a_well_formed_response(self):
        resp = _fake_ptr_response(0x1234, "50.1.168.192.in-addr.arpa", "printer.local")
        assert _parse_ptr_response(resp, 0x1234) == "printer.local"

    def test_mdns_responses_with_transaction_id_zero_are_accepted(self):
        # mDNS responders conventionally reply with id 0 regardless of
        # what the query used.
        resp = _fake_ptr_response(0x0000, "50.1.168.192.in-addr.arpa", "sonos.local")
        assert _parse_ptr_response(resp, 0xBEEF) == "sonos.local"

    def test_mismatched_transaction_id_is_rejected(self):
        resp = _fake_ptr_response(0x1111, "50.1.168.192.in-addr.arpa", "printer.local")
        assert _parse_ptr_response(resp, 0x2222) is None

    def test_error_rcode_is_rejected(self):
        header = struct.pack(">HHHHHH", 0x1234, 0x8183, 0, 0, 0, 0)  # RCODE=3 NXDOMAIN
        assert _parse_ptr_response(header, 0x1234) is None

    def test_truncated_or_garbage_data_never_raises(self):
        assert _parse_ptr_response(b"", 1) is None
        assert _parse_ptr_response(b"\x00" * 11, 1) is None
        assert _parse_ptr_response(b"not a dns packet at all!!", 1) is None


class TestNetbiosEncoding:
    def test_wildcard_name_encodes_to_32_bytes(self):
        encoded = _encode_netbios_name(_NBNS_WILDCARD_NAME)
        assert len(encoded) == 32
        # '*' is 0x2A -> nibbles 0x2 and 0xA -> 'A'+2='C', 'A'+10='K'.
        assert encoded[0:2] == b"CK"

    def test_query_has_the_expected_shape(self):
        query = _build_nbns_query(0xABCD)
        tid = struct.unpack(">H", query[0:2])[0]
        assert tid == 0xABCD
        assert query[12] == 32  # name length byte
        qtype, qclass = struct.unpack(">HH", query[-4:])
        assert (qtype, qclass) == (0x21, 1)


class TestParseNbnsResponse:
    @staticmethod
    def _fake_nbns_response(name: str, *, suffix: int = 0x00, group: bool = False) -> bytes:
        header = struct.pack(">HHHHHH", 0xABCD, 0x8400, 0, 1, 0, 0)
        rr_name = struct.pack("B", 32) + _encode_netbios_name(_NBNS_WILDCARD_NAME) + b"\x00"
        padded = name.encode("ascii").ljust(15, b" ")[:15]
        flags = 0x8000 if group else 0x0400
        name_entry = padded + bytes([suffix]) + struct.pack(">H", flags)
        rdata = bytes([1]) + name_entry
        rr = rr_name + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
        return header + rr

    def test_decodes_workstation_name(self):
        resp = self._fake_nbns_response("DESKTOP-ABC")
        assert _parse_nbns_response(resp) == "DESKTOP-ABC"

    def test_group_names_are_skipped_in_favour_of_the_unique_name(self):
        group_entry = self._fake_nbns_response("WORKGROUP", group=True)
        # A pure group-name response has nothing usable to return.
        assert _parse_nbns_response(group_entry) is None

    def test_non_workstation_suffix_is_skipped(self):
        # Suffix 0x20 is the "File Server" service name, not 0x00
        # (Workstation/Computer name) - not what we want back.
        resp = self._fake_nbns_response("FILESERVER", suffix=0x20)
        assert _parse_nbns_response(resp) is None

    def test_truncated_or_garbage_data_never_raises(self):
        assert _parse_nbns_response(b"") is None
        assert _parse_nbns_response(b"\x00" * 12) is None
        assert _parse_nbns_response(b"garbage, not nbns") is None
