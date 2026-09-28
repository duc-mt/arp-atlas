# backward-compatibility shim — real server now lives in backend/app/server/
# ruff: noqa: F401

from backend.app.server.server import run_dashboard
from backend.app.server.handler import DashboardHandler, ReuseTCPServer, DASHBOARD_HTML
