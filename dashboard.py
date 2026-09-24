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
        
        async function clearHistory() {
            if (!confirm("Are you sure you want to clear all scan history?")) return;
            try {
                const response = await fetch('/api/clear', { method: 'POST' });
                if (response.ok) {
                    document.getElementById('content').innerHTML = '<p class="text-slate-500 p-4">History cleared.</p>';
                } else {
                    alert("Failed to clear history");
                }
            } catch (e) {
                alert("Error clearing history");
            }
        }
        
        async function triggerScan() {
            const network = document.getElementById('network-input').value;
            const scanPorts = document.getElementById('scan-ports').checked;
            const btn = document.getElementById('scan-btn');
            
            if (!network) {
                alert("Please enter a network address");
                return;
            }
            
            btn.disabled = true;
            btn.innerText = "Scanning...";
            btn.classList.add("opacity-50");
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({network: network, scan_ports: scanPorts})
                });
                const result = await response.json();
                if (response.ok) {
                    await fetchHistory();
                    btn.innerText = "Success!";
                    setTimeout(() => { btn.innerText = "Scan Network"; }, 2000);
                } else {
                    alert("Error: " + result.message);
                }
            } catch (error) {
                alert("Failed to trigger scan");
            } finally {
                btn.disabled = false;
                btn.classList.remove("opacity-50");
                if (btn.innerText === "Scanning...") {
                    btn.innerText = "Scan Network";
                }
            }
        }

        async function fetchHistory() {
            const btn = document.getElementById('refresh-btn');
            if (btn) {
                btn.disabled = true;
                btn.innerText = "Refreshing...";
                btn.classList.add("opacity-50");
            }
            // Clear the dashboard screen immediately for visual feedback
            const container = document.getElementById('content');
            if (container) {
                container.innerHTML = '<p class="p-4 text-slate-500">Refreshing data...</p>';
            }
            try {
                const response = await fetch('/scan_history.json?t=' + new Date().getTime());
                const data = await response.json();
                renderDashboard(data);
            } catch (error) {
                console.error("No history found or error fetching", error);
                document.getElementById('content').innerHTML = '<p class="text-red-500 p-4">No scan history found. Please run a scan first.</p>';
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.classList.remove("opacity-50");
                    setTimeout(() => { btn.innerText = "Refresh"; }, 500);
                }
            }
        }

        function renderDashboard(data) {
            const container = document.getElementById('content');
            container.innerHTML = '';
            
            // Sort networks by timestamp descending (newest first)
            const sortedEntries = Object.entries(data).sort((a, b) => {
                return new Date(b[1].timestamp) - new Date(a[1].timestamp);
            });
            
            for (const [network, info] of sortedEntries) {
                let totalHosts = 1;
                if (network.includes('/')) {
                    const prefix = parseInt(network.split('/')[1], 10);
                    if (!network.includes(':')) {
                        const totalIps = Math.pow(2, 32 - prefix);
                        totalHosts = prefix <= 30 ? totalIps - 2 : totalIps;
                    }
                }
                const foundHosts = info.devices.length;
                let pct = 0;
                if (totalHosts > 0) {
                    pct = (foundHosts / totalHosts) * 100;
                    if (pct > 100) pct = 100;
                }
                
                let colorClass = "bg-red-500";
                if (pct >= 50) colorClass = "bg-emerald-500";
                else if (pct >= 10) colorClass = "bg-amber-500";

                let html = `<div class="bg-white rounded-lg shadow-md mb-6 p-6">
                    <h2 class="text-2xl font-bold mb-2 text-slate-800">Network: ${network}</h2>
                    <p class="text-sm text-slate-500 mb-4">Last scanned: ${new Date(info.timestamp).toLocaleString()}</p>
                    
                    <div class="mb-6">
                        <div class="flex justify-between text-sm mb-1">
                            <span class="font-medium text-slate-700">${foundHosts} of ${totalHosts} addresses found</span>
                            <span class="font-medium text-slate-700">${pct.toFixed(1)}%</span>
                        </div>
                        <div class="w-full bg-slate-200 rounded-full h-2.5">
                            <div class="${colorClass} h-2.5 rounded-full transition-all duration-500" style="width: ${pct}%"></div>
                        </div>
                    </div>
                    
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
            <div class="flex flex-col sm:flex-row items-center justify-between h-auto sm:h-16 py-4 sm:py-0">
                <div class="flex items-center mb-4 sm:mb-0">
                    <span class="font-bold text-white text-xl">Network Hunter</span>
                </div>
                <div class="flex items-center space-x-4">
                    <input type="text" id="network-input" placeholder="e.g. 192.168.1.0/24" class="px-3 py-2 rounded border border-gray-300 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400">
                    <label class="text-white text-sm flex items-center">
                        <input type="checkbox" id="scan-ports" class="mr-2"> Scan Ports
                    </label>
                    <button onclick="triggerScan()" id="scan-btn" class="bg-emerald-500 hover:bg-emerald-400 text-white px-4 py-2 rounded shadow transition text-sm font-semibold">Scan Network</button>
                    <button onclick="fetchHistory()" id="refresh-btn" class="bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded shadow transition text-sm font-semibold">Refresh</button>
                    <button onclick="clearHistory()" id="clear-btn" class="bg-red-500 hover:bg-red-400 text-white px-4 py-2 rounded shadow transition text-sm font-semibold">Clear</button>
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
    
    def do_POST(self) -> None:
        if self.path == '/api/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                network = data.get('network')
                scan_ports = data.get('scan_ports', False)
                
                import main
                valid_network = main.validate_network(network)
                devices = main.scan_network(valid_network)
                main.enrich_devices(devices)
                
                if scan_ports:
                    main.scan_devices_ports(devices)
                
                main.save_scan(main.HISTORY_FILE, valid_network, devices)
                
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "network": valid_network}).encode('utf-8'))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
        elif self.path == '/api/clear':
            try:
                if os.path.exists("scan_history.json"):
                    os.remove("scan_history.json")
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
            except Exception as e:
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode('utf-8'))
        elif self.path.startswith('/scan_history.json'):
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
        elif self.path == '/api/clear':
            try:
                if os.path.exists("scan_history.json"):
                    os.remove("scan_history.json")
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
            except Exception as e:
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def run_dashboard(port: int = 8080) -> None:
    print(f"Starting web dashboard at http://localhost:{port}")
    with ReuseTCPServer(("", port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard.")
