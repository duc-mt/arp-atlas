"""
==============================================================================
Module Name:   dashboard.py
Description:   Implementation and logic for dashboard.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 dashboard.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""
# backward-compatibility shim — real server now lives in backend/app/server/
# ruff: noqa: F401

from backend.app.server.server import run_dashboard
from backend.app.server.handler import DashboardHandler, ReuseTCPServer, DASHBOARD_HTML
