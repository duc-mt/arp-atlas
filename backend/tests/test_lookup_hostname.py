"""
==============================================================================
Module Name:   test_lookup_hostname.py
Description:   Source module test_lookup_hostname.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_lookup_hostname.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import asyncio
import socket
from unittest import mock

from backend.app.services.enrichment import lookup_hostname


class TestLookupHostname:
    def test_returns_the_hostname_on_success(self):
        with mock.patch(
            "socket.getnameinfo",
            return_value=("printer.local", "0"),
        ):
            assert lookup_hostname("192.168.1.50") == "printer.local"

    def test_no_ptr_record_returns_none(self):
        with mock.patch("socket.getnameinfo", side_effect=socket.gaierror("no PTR")):
            assert lookup_hostname("192.168.1.50") is None

    def test_timeout_returns_none_not_an_exception(self):
        # We need to simulate the async wait_for timing out.
        # However, asyncio wraps `getnameinfo` in a thread, so raising `asyncio.TimeoutError`
        # directly from the mock doesn't always work if it's called inside run_in_executor.
        # But we can just mock `_lookup_hostname_async` for a pure timeout test,
        # or we can just mock the asyncio wait_for.
        def _mock_wait_for(coro, timeout=None):
            if hasattr(coro, "close"):
                coro.close()
            elif hasattr(coro, "cancel"):
                coro.cancel()
            raise asyncio.TimeoutError()

        with mock.patch("asyncio.wait_for", side_effect=_mock_wait_for):
            assert lookup_hostname("192.168.1.50") is None
