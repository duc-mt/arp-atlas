"""Tests for main.lookup_hostname().

socket.gethostbyaddr() is always mocked - these tests never perform a
real DNS lookup.
"""

from __future__ import annotations

import socket
from unittest import mock

import main


class TestLookupHostname:
    def test_returns_the_hostname_on_success(self):
        with mock.patch(
            "socket.gethostbyaddr",
            return_value=("printer.local", [], ["192.168.1.50"]),
        ):
            assert main.lookup_hostname("192.168.1.50") == "printer.local"

    def test_no_ptr_record_returns_none(self):
        with mock.patch(
            "socket.gethostbyaddr", side_effect=socket.herror("no PTR")
        ):
            assert main.lookup_hostname("192.168.1.50") is None

    def test_timeout_returns_none_not_an_exception(self):
        with mock.patch(
            "socket.gethostbyaddr", side_effect=socket.timeout()
        ):
            assert main.lookup_hostname("192.168.1.50") is None

    def test_restores_the_previous_default_socket_timeout(self):
        socket.setdefaulttimeout(5.0)
        try:
            with mock.patch(
                "socket.gethostbyaddr",
                return_value=("host", [], ["192.168.1.50"]),
            ):
                main.lookup_hostname("192.168.1.50", timeout=0.1)
            assert socket.getdefaulttimeout() == 5.0
        finally:
            socket.setdefaulttimeout(None)
