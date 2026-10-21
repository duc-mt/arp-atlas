"""
==============================================================================
Module Name:   test_server.py
Description:   Tests for run_dashboard() in backend/app/server/server.py:
               how the server is built, which address and port it binds,
               and that Ctrl-C shuts it down cleanly and frees the port.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-21
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_server.py
Notes:         Requires Python 3.10+. Every test that starts a real server
               binds an ephemeral loopback port and is bounded by timeouts,
               so a failure can't hang the suite.
==============================================================================
"""

from __future__ import annotations

import http.client
import inspect
import json
import os
import signal
import socket
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any, ClassVar
from unittest import mock

import pytest

from backend.app.server import server as server_module
from backend.app.server.handler import DashboardHandler, ReuseTCPServer
from backend.app.server.server import run_dashboard

_WAIT = 5.0  # seconds any test waits for the server before failing


class RecordingServer(ReuseTCPServer):
    """The real server, plus a note of each instance so a test can see which
    address it bound - `run_dashboard(port=0)` otherwise gives no way to
    learn the ephemeral port the OS picked."""

    instances: ClassVar[list[RecordingServer]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        RecordingServer.instances.append(self)


@pytest.fixture
def recording_server() -> Iterator[type[RecordingServer]]:
    RecordingServer.instances = []
    with mock.patch.object(server_module, "ReuseTCPServer", RecordingServer):
        yield RecordingServer


def _wait_for_instance(timeout: float = _WAIT) -> RecordingServer:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if RecordingServer.instances:
            return RecordingServer.instances[0]
        time.sleep(0.01)
    raise AssertionError("run_dashboard() never created its server")


def _get_status(port: int) -> tuple[int, Any]:
    """GET /api/status, retrying until the server is accepting - which also
    proves serve_forever() is running, not merely that the socket is bound."""
    deadline = time.monotonic() + _WAIT
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            conn.request("GET", "/api/status")
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        except (OSError, http.client.HTTPException) as e:
            last_error = e
            time.sleep(0.02)
        finally:
            conn.close()
    raise AssertionError(f"the dashboard never answered: {last_error!r}")


def _stop_server_if_running() -> None:
    """Ask the recorded server to stop (no signal involved)."""
    if RecordingServer.instances:
        RecordingServer.instances[0].shutdown()


def _port_is_free(port: int) -> bool:
    """Can a fresh listener bind this port right now?"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _accepts_connections(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
    except OSError:
        return False
    return True


class TestRunDashboardWiring:
    """run_dashboard()'s own logic, with the server replaced by a stub so no
    socket is opened."""

    @staticmethod
    def _stub_server() -> mock.MagicMock:
        stub_cls = mock.MagicMock(name="ReuseTCPServer")
        stub = stub_cls.return_value
        stub.__enter__.return_value = stub
        stub.__exit__.return_value = False  # never swallow an exception
        return stub_cls

    def test_binds_loopback_only_on_the_requested_port_with_the_dashboard_handler(self) -> None:
        stub_cls = self._stub_server()
        with mock.patch.object(server_module, "ReuseTCPServer", stub_cls):
            run_dashboard(port=9123)

        stub_cls.assert_called_once_with(("127.0.0.1", 9123), DashboardHandler)
        stub_cls.return_value.serve_forever.assert_called_once_with()

    def test_default_port_is_8080(self) -> None:
        assert inspect.signature(run_dashboard).parameters["port"].default == 8080

        stub_cls = self._stub_server()
        with mock.patch.object(server_module, "ReuseTCPServer", stub_cls):
            run_dashboard()
        assert stub_cls.call_args.args[0] == ("127.0.0.1", 8080)

    def test_announces_the_url_before_serving(self, capsys: pytest.CaptureFixture[str]) -> None:
        stub_cls = self._stub_server()
        seen_at_serve: list[str] = []
        stub_cls.return_value.serve_forever.side_effect = lambda: seen_at_serve.append(
            capsys.readouterr().out
        )
        with mock.patch.object(server_module, "ReuseTCPServer", stub_cls):
            run_dashboard(port=9123)

        assert "Starting web dashboard at http://localhost:9123" in seen_at_serve[0]

    def test_ctrl_c_ends_the_call_normally_and_closes_the_server(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub_cls = self._stub_server()
        stub_cls.return_value.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(server_module, "ReuseTCPServer", stub_cls):
            try:
                run_dashboard(port=9123)
            except KeyboardInterrupt:  # pragma: no cover - only if run_dashboard() regresses
                # Fail the test rather than let pytest treat it as the user's Ctrl-C
                # and abort the whole session.
                pytest.fail("KeyboardInterrupt escaped run_dashboard()")

        assert "Shutting down dashboard." in capsys.readouterr().out
        stub_cls.return_value.__exit__.assert_called_once()  # the with-block closed it

    def test_other_errors_are_not_swallowed_but_the_server_is_still_closed(self) -> None:
        stub_cls = self._stub_server()
        stub_cls.return_value.serve_forever.side_effect = RuntimeError("boom")
        with (
            mock.patch.object(server_module, "ReuseTCPServer", stub_cls),
            pytest.raises(RuntimeError, match="boom"),
        ):
            run_dashboard(port=9123)

        stub_cls.return_value.__exit__.assert_called_once()

    def test_a_port_that_cannot_be_bound_is_reported_not_hidden(self) -> None:
        stub_cls = mock.MagicMock(side_effect=OSError(98, "Address already in use"))
        with (
            mock.patch.object(server_module, "ReuseTCPServer", stub_cls),
            pytest.raises(OSError, match="Address already in use"),
        ):
            run_dashboard(port=9123)


class TestServerClass:
    def test_is_a_threaded_tcp_server_with_the_documented_flags(self) -> None:
        import socketserver

        assert issubclass(ReuseTCPServer, socketserver.ThreadingMixIn)
        assert issubclass(ReuseTCPServer, socketserver.TCPServer)
        assert ReuseTCPServer.allow_reuse_address is True
        assert ReuseTCPServer.daemon_threads is True

    def test_can_be_instantiated_bound_and_closed_without_serving(self) -> None:
        with ReuseTCPServer(("127.0.0.1", 0), DashboardHandler) as httpd:
            host, port = httpd.server_address[:2]
            assert host == "127.0.0.1"
            assert isinstance(port, int)
            assert port > 0  # the OS picked a real port
            assert httpd.RequestHandlerClass is DashboardHandler
        assert _port_is_free(port)  # leaving the with-block released it


class TestRealServer:
    """run_dashboard() for real: a socket is bound, requests are answered,
    and the server stops when asked."""

    def _start(self, recording_server: Any) -> tuple[threading.Thread, RecordingServer, int]:
        thread = threading.Thread(target=run_dashboard, kwargs={"port": 0}, daemon=True)
        thread.start()
        instance = _wait_for_instance()
        return thread, instance, int(instance.server_address[1])

    def test_binds_the_loopback_interface_on_the_requested_port(
        self, recording_server: Any
    ) -> None:
        thread, instance, port = self._start(recording_server)
        try:
            assert instance.server_address[0] == "127.0.0.1"  # not 0.0.0.0
            assert instance.socket.getsockname() == ("127.0.0.1", port)
            assert _get_status(port) == (200, {"scanning": False})
        finally:
            instance.shutdown()
            thread.join(timeout=_WAIT)
        assert not thread.is_alive()

    def test_shutdown_stops_serving_and_frees_the_port(self, recording_server: Any) -> None:
        thread, instance, port = self._start(recording_server)
        _get_status(port)  # it is genuinely serving
        assert not _port_is_free(port)

        instance.shutdown()  # what serve_forever()'s caller does on a stop request
        thread.join(timeout=_WAIT)

        assert not thread.is_alive(), "run_dashboard() did not return after shutdown()"
        assert not _accepts_connections(port)
        assert _port_is_free(port)  # a restart can bind the same port straight away

    def test_a_busy_port_raises_instead_of_silently_sharing_it(self) -> None:
        if sys.platform == "win32":
            pytest.skip("SO_REUSEADDR lets a second listener bind on Windows")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as squatter:
            squatter.bind(("127.0.0.1", 0))
            squatter.listen(1)
            port = squatter.getsockname()[1]

            with pytest.raises(OSError):
                run_dashboard(port=port)


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(signal, "SIGINT"),
    reason="delivers a real SIGINT to this process, POSIX only",
)
@pytest.mark.skipif(
    threading.current_thread() is not threading.main_thread(),
    reason="Python delivers signals to the main thread only",
)
class TestRealSignal:
    def test_sigint_shuts_the_dashboard_down_cleanly(
        self, recording_server: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """What happens when someone presses Ctrl-C: a real SIGINT reaches
        serve_forever(), run_dashboard() returns normally, and the port is
        released. A watchdog bounds the wait so a regression can't hang the
        suite, and the signal is only sent once the server is serving so it
        can't land before run_dashboard()'s try block."""
        outcome: dict[str, Any] = {}

        def interrupt_when_serving() -> None:
            try:
                instance = _wait_for_instance()
                port = int(instance.server_address[1])
                outcome["port"] = port
                _get_status(port)  # serve_forever() is running
                os.kill(os.getpid(), signal.SIGINT)
            except BaseException as e:  # report from the main thread, don't die silently
                outcome["helper_error"] = e
                # Unblock run_dashboard() without a signal: a SIGINT sent when the
                # server isn't serving yet would abort the whole pytest session.
                _stop_server_if_running()

        helper = threading.Thread(target=interrupt_when_serving, daemon=True)
        helper.start()
        # Backstop: if SIGINT somehow didn't stop the server, stop it by hand
        # rather than blocking the whole test run forever.
        watchdog = threading.Timer(_WAIT * 3, _stop_server_if_running)
        watchdog.start()
        try:
            run_dashboard(port=0)
        except KeyboardInterrupt:  # pragma: no cover - only if run_dashboard() regresses
            pytest.fail("KeyboardInterrupt escaped run_dashboard()")
        finally:
            watchdog.cancel()
            helper.join(timeout=_WAIT)

        assert "helper_error" not in outcome, outcome.get("helper_error")
        assert "Shutting down dashboard." in capsys.readouterr().out
        assert _port_is_free(outcome["port"])
        assert not _accepts_connections(outcome["port"])
