
"""
==============================================================================
Module Name:   server.py
Description:   Dashboard server entry point.
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


from backend.app.server.handler import DashboardHandler, ReuseTCPServer


def run_dashboard(port: int = 8080) -> None:
    """Start the ARP Atlas web dashboard on the given port."""
    print(f"Starting web dashboard at http://localhost:{port}")
    with ReuseTCPServer(("127.0.0.1", port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard.")
