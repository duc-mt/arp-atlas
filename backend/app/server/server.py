"""
==============================================================================
Module Name:   server.py
Description:   Source module server.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 server.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import signal
import threading
from types import FrameType

from backend.app.server.handler import DashboardHandler, ReuseTCPServer


def _terminate(signum: int, frame: FrameType | None) -> None:
    """SIGTERM is what `docker stop`, systemd and `kill` send. Treat it exactly
    like Ctrl-C, so the server is shut down and closed instead of the process
    being killed mid-request."""
    raise KeyboardInterrupt


def run_dashboard(port: int = 8080) -> None:
    """Start the ARP Atlas web dashboard on the given port.

    Returns normally on Ctrl-C (SIGINT) or SIGTERM, after closing the server
    and freeing the port.
    """
    # Signal handlers can only be installed from the main thread; when this is
    # called from another thread (tests, an embedding app) the caller owns
    # signal handling.
    installed = threading.current_thread() is threading.main_thread()
    previous_handler = signal.signal(signal.SIGTERM, _terminate) if installed else None

    print(f"Starting web dashboard at http://localhost:{port}")
    try:
        with ReuseTCPServer(("127.0.0.1", port), DashboardHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard.")
    finally:
        if installed:
            # signal.signal() returns None when the old handler wasn't set from Python.
            signal.signal(
                signal.SIGTERM, previous_handler if previous_handler is not None else signal.SIG_DFL
            )
