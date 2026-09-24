from __future__ import annotations

import typing
"""Tests for main.lookup_hostname().

socket.getnameinfo() is always mocked - these tests never perform a
real DNS lookup.
"""


import asyncio
import socket
from unittest import mock

import main


class TestLookupHostname:
    def test_returns_the_hostname_on_success(self):
        with mock.patch(
            "socket.getnameinfo",
            return_value=("printer.local", "0"),
        ):
            assert main.lookup_hostname("192.168.1.50") == "printer.local"

    def test_no_ptr_record_returns_none(self):
        with mock.patch(
            "socket.getnameinfo", side_effect=socket.gaierror("no PTR")
        ):
            assert main.lookup_hostname("192.168.1.50") is None

    def test_timeout_returns_none_not_an_exception(self):
        # We need to simulate the async wait_for timing out.
        # However, asyncio wraps `getnameinfo` in a thread, so raising `asyncio.TimeoutError`
        # directly from the mock doesn't always work if it's called inside run_in_executor.
        # But we can just mock `_lookup_hostname_async` for a pure timeout test,
        # or we can just mock the asyncio wait_for.
        with mock.patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            assert main.lookup_hostname("192.168.1.50") is None
