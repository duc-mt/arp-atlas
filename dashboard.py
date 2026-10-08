import http.server
import json
import os
import socketserver
import threading
from typing import Any

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Hunter Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        async function fetchHistory() {
            try {
                const response = await fetch('/scan_history.json');
                const data = await response.json();
                renderDashboard(data);
            } catch (error) {
                console.error("No history found or error fetching", error);
                document.getElementById('content').innerHTML = '<p class="text-red-500 p-4">No scan history found. Please run a scan first.</p>';
            }
        }

        function renderDashboard(data) {
            const container = document.getElementById('content');
            container.innerHTML = '';
            
            for (const [network, info] of Object.entries(data)) {
                let html = `<div class="bg-white rounded-lg shadow-md mb-6 p-6">
                    <h2 class="text-2xl font-bold mb-2 text-slate-800">Network: ${network}</h2>
                    <p class="text-sm text-slate-500 mb-4">Last scanned: ${new Date(info.timestamp).toLocaleString()}</p>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-sm whitespace-nowrap">
                            <thead class="uppercase tracking-wider border-b-2 border-slate-200 bg-slate-50">
                                <tr>
                                    <th scope="col" class="px-6 py-4">IP Address</th>
                                    <th scope="col" class="px-6 py-4">MAC Address</th>
                                    <th scope="col" class="px-6 py-4">Vendor</th>
                                    <th scope="col" class="px-6 py-4">Hostname</th>
                                    <th scope="col" class="px-6 py-4">Ports</th>
                                    <th scope="col" class="px-6 py-4">Role</th>
                                </tr>
                            </thead>
                            <tbody>`;
                
                info.devices.forEach(device => {
                    const isRandom = device.is_randomized ? '<span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800">Random</span>' : '';
                    const vendor = device.vendor || '-';
                    const hostname = device.hostname || '-';
                    const ports = (device.open_ports || []).join(', ') || '-';
                    const role = device.role || '-';
                    
                    html += `<tr class="border-b border-slate-100 hover:bg-slate-50">
                        <td class="px-6 py-4 font-mono">${device.ip}</td>
                        <td class="px-6 py-4 font-mono">${device.mac}${isRandom}</td>
                        <td class="px-6 py-4">${vendor}</td>
                        <td class="px-6 py-4">${hostname}</td>
                        <td class="px-6 py-4 font-mono">${ports}</td>
                        <td class="px-6 py-4 capitalize">${role}</td>
                    </tr>`;
                });
                
                html += `</tbody></table></div></div>`;
                container.innerHTML += html;
            }
        }
        
        window.onload = fetchHistory;
    </script>
</head>
<body class="bg-slate-100 min-h-screen font-sans">
    <nav class="bg-indigo-600 shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center">
                    <span class="font-bold text-white text-xl">Network Hunter</span>
                </div>
                <div>
                    <button onclick="fetchHistory()" class="bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded shadow transition">Refresh</button>
                </div>
            </div>
        </div>
    </nav>
    <main class="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8" id="content">
        <p class="p-4 text-slate-500">Loading dashboard...</p>
    </main>
</body>
</html>
"""

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode('utf-8'))
        elif self.path == '/scan_history.json':
            if os.path.exists("scan_history.json"):
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                with open("scan_history.json", "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_dashboard(port: int = 8080) -> None:
    print(f"Starting web dashboard at http://localhost:{port}")
    with socketserver.TCPServer(("", port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard.")
