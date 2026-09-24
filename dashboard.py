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
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
            const target = document.getElementById('scan-target').value.trim();
            const iface = document.getElementById('iface-select').value;
            const scanPorts = document.getElementById('scan-ports').checked;
            const btn = document.getElementById('scan-btn');
            
            if (!target) {
                alert("Please enter a target (CIDR or IP-IP range)");
                return;
            }
            
            btn.disabled = true;
            btn.innerText = "Scanning...";
            btn.classList.add("opacity-50");
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, iface: iface, scan_ports: scanPorts})
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

        window.currentData = null;
        window.currentAvailableIps = [];
        
        function ipToLong(ip) {
            return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
        }
        function longToIp(long) {
            return `${(long >>> 24) & 255}.${(long >>> 16) & 255}.${(long >>> 8) & 255}.${long & 255}`;
        }
        
        function getAvailableIpsRange(startIp, endIp, foundIps) {
            const startLong = ipToLong(startIp);
            const endLong = ipToLong(endIp);
            const available = [];
            const foundSet = new Set(foundIps);
            for (let i = startLong; i <= endLong; i++) {
                const ipStr = longToIp(i);
                if (!foundSet.has(ipStr)) {
                    available.push(ipStr);
                }
            }
            return available;
        }

        function getAvailableIpsCidr(cidr, foundIps) {
            const parts = cidr.split('/');
            if (parts.length !== 2) return [];
            const prefix = parseInt(parts[1], 10);
            if (prefix > 30 || prefix < 8) return [];
            const ipLong = ipToLong(parts[0]);
            const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
            const networkLong = (ipLong & mask) >>> 0;
            const broadcastLong = (networkLong | ~mask) >>> 0;
            
            const available = [];
            const foundSet = new Set(foundIps);
            for (let i = networkLong + 1; i < broadcastLong; i++) {
                const ipStr = longToIp(i);
                if (!foundSet.has(ipStr)) {
                    available.push(ipStr);
                }
            }
            return available;
        }

        function exportScanCsv(network) {
            if (!window.currentData || !window.currentData[network]) return;
            const info = window.currentData[network];
            
            let csvContent = "data:text/csv;charset=utf-8,IP Address,MAC Address,Vendor,Hostname,Ports,Role\\n";
            
            info.devices.forEach(device => {
                const ip = device.ip || '';
                const mac = device.mac || '';
                const vendor = '"' + (device.vendor || '-').replace(/"/g, '""') + '"';
                const hostname = '"' + (device.hostname || '-').replace(/"/g, '""') + '"';
                const ports = '"' + (device.open_ports ? device.open_ports.join(', ') : '-') + '"';
                const role = device.role || '-';
                
                csvContent += `${ip},${mac},${vendor},${hostname},${ports},${role}\\n`;
            });
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", `scan_${network.replace(/[^a-zA-Z0-9]/g, '_')}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        function showAvailableAddresses(network) {
            if (!window.currentData || !window.currentData[network]) return;
            const info = window.currentData[network];
            const foundIps = info.devices.map(d => d.ip);
            
            const baseNet = network.split(' on ')[0];
            let available = [];
            if (baseNet.includes('-')) {
                const parts = baseNet.split('-');
                if (parts.length === 2) {
                    available = getAvailableIpsRange(parts[0], parts[1], foundIps);
                }
            } else if (baseNet.includes('/')) {
                available = getAvailableIpsCidr(baseNet, foundIps);
            }
            window.currentAvailableIps = available;
            
            document.getElementById('available-title').innerText = `Available Addresses (${available.length})`;
            const listEl = document.getElementById('available-list');
            listEl.innerHTML = available.map(ip => `<li>${ip}</li>`).join('');
            document.getElementById('available-modal').classList.remove('hidden');
        }

        function closeAvailableModal() {
            document.getElementById('available-modal').classList.add('hidden');
        }

        function copyAvailable() {
            navigator.clipboard.writeText(window.currentAvailableIps.join('\\n')).then(() => {
                alert('Copied ' + window.currentAvailableIps.length + ' addresses to clipboard!');
            });
        }

        function exportAvailableCsv() {
            let csvContent = "data:text/csv;charset=utf-8,IP Address\\n" + window.currentAvailableIps.join("\\n");
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "available_ips.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        async function fetchHistory() {
            const btn = document.getElementById('refresh-btn');
            if (btn) {
                btn.disabled = true;
                btn.innerText = "Refreshing...";
                btn.classList.add("opacity-50");
            }
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
            window.currentData = data;
            const container = document.getElementById('content');
            container.innerHTML = '';
            
            const sortedEntries = Object.entries(data).sort((a, b) => {
                return new Date(b[1].timestamp) - new Date(a[1].timestamp);
            });
            
            let chartIdx = 0;
            let finalHtml = "";
            const chartsToInit = [];
            
            for (const [network, info] of sortedEntries) {
                chartIdx++;
                const chartId = `chart-${chartIdx}`;
                const foundHosts = info.devices.length;
                
                let stats = info.stats || { responded: foundHosts, wrong_iface: 0, no_response: 0 };
                let totalHosts = stats.responded + stats.wrong_iface + stats.no_response;
                if (totalHosts <= 0) totalHosts = 1;
                let pct = (stats.responded / totalHosts) * 100;

                let html = `<div class="bg-white rounded-lg shadow-md mb-6 p-6">
                    <div class="flex justify-between items-start mb-2">
                        <h2 class="text-2xl font-bold text-slate-800">Network: ${network}</h2>
                        <div class="flex space-x-2">
                            <button onclick="exportScanCsv('${network}')" class="bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 px-4 py-1.5 rounded shadow-sm text-sm font-semibold transition">Export Data (CSV)</button>
                            <button onclick="showAvailableAddresses('${network}')" class="bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 px-4 py-1.5 rounded shadow-sm text-sm font-semibold transition">View Available Addresses</button>
                        </div>
                    </div>
                    <p class="text-sm text-slate-500 mb-4">Last scanned: ${new Date(info.timestamp).toLocaleString()}</p>
                    
                    <div class="flex flex-col md:flex-row gap-6 mb-6 items-center">
                        <div class="flex-1 w-full">
                            <div class="flex justify-between text-sm mb-1">
                                <span class="font-medium text-slate-700">${stats.responded} of ${totalHosts} addresses found</span>
                                <span class="font-medium text-slate-700">${pct.toFixed(1)}%</span>
                            </div>
                            <div class="w-full bg-slate-200 rounded-full h-2.5">
                                <div class="${pct >= 50 ? 'bg-emerald-500' : pct >= 10 ? 'bg-amber-500' : 'bg-red-500'} h-2.5 rounded-full transition-all duration-500" style="width: ${pct}%"></div>
                            </div>
                        </div>
                        <div class="w-48 h-48 relative">
                            <canvas id="${chartId}"></canvas>
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
                finalHtml += html;
                
                chartsToInit.push({
                    id: chartId,
                    stats: stats
                });
            }
            
            container.innerHTML = finalHtml;
            
            chartsToInit.forEach(c => {
                new Chart(document.getElementById(c.id), {
                    type: 'pie',
                    data: {
                        labels: ['Responded', 'Other Interface', 'No Response'],
                        datasets: [{
                            data: [c.stats.responded, c.stats.wrong_iface, c.stats.no_response],
                            backgroundColor: ['#10b981', '#f59e0b', '#e2e8f0']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
            });
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
                <div class="flex flex-wrap items-center gap-2">
                    <select id="iface-select" class="px-3 py-1.5 rounded text-slate-700 bg-white border-0">
                        <!-- IFACE_OPTIONS -->
                    </select>
                    <input type="text" id="scan-target" placeholder="192.168.1.0/24 or 10.0.0.1-10.0.0.50" class="px-3 py-1.5 rounded text-slate-700 w-64 border-0 focus:ring-2 focus:ring-indigo-300">
                    <label class="flex items-center text-white text-sm font-medium">
                        <input type="checkbox" id="scan-ports" class="mr-2"> Scan Ports
                    </label>
                    <button onclick="triggerScan()" id="scan-btn" class="bg-emerald-500 hover:bg-emerald-400 text-white px-4 py-2 rounded shadow transition text-sm font-semibold">Scan Network</button>
                    
                    <button onclick="clearHistory()" class="bg-red-500 hover:bg-red-400 text-white px-4 py-2 rounded shadow transition text-sm font-semibold">Clear</button>
                </div>
            </div>
        </div>
    </nav>
    <main class="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8" id="content">
        <p class="p-4 text-slate-500">Loading dashboard...</p>
    </main>

    <!-- Available Addresses Modal -->
    <div id="available-modal" class="fixed inset-0 bg-slate-900 bg-opacity-50 hidden z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-lg max-h-[80vh] flex flex-col">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 id="available-title" class="text-lg font-bold text-slate-800">Available Addresses</h3>
                <button onclick="closeAvailableModal()" class="text-slate-400 hover:text-slate-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 overflow-y-auto flex-1 bg-slate-50">
                <ul id="available-list" class="space-y-1 font-mono text-sm text-slate-700"></ul>
            </div>
            <div class="px-6 py-4 border-t border-slate-200 bg-slate-100 flex justify-end space-x-3 rounded-b-lg">
                <button onclick="copyAvailable()" class="bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 px-4 py-2 rounded shadow-sm text-sm font-semibold transition">Copy to Clipboard</button>
                <button onclick="exportAvailableCsv()" class="bg-emerald-500 hover:bg-emerald-400 text-white px-4 py-2 rounded shadow-sm text-sm font-semibold transition">Export to CSV</button>
            </div>
        </div>
    </div>
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
                target_input = data.get('target', '').strip()
                iface = data.get('iface')
                scan_ports = data.get('scan_ports', False)
                
                import ipaddress
                import scapy.all as scapy
                import main
                
                if "-" in target_input:
                    start_ip, end_ip = target_input.split("-", 1)
                    start_obj = ipaddress.IPv4Address(start_ip.strip())
                    end_obj = ipaddress.IPv4Address(end_ip.strip())
                    if start_obj > end_obj:
                        start_obj, end_obj = end_obj, start_obj
                    target_ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_obj), int(end_obj) + 1)]
                    network_str = f"{start_obj}-{end_obj}"
                else:
                    net = ipaddress.ip_network(target_input, strict=False)
                    target_ips = [str(ip) for ip in net.hosts()]
                    network_str = str(net)
                if iface:
                    network_str += f" on {iface}"
                
                devices = main.scan_network(target_ips, iface=iface)
                
                wrong_iface_count = 0
                for ip in target_ips:
                    route = scapy.conf.route.route(ip)[0]
                    if hasattr(route, "name"): route = route.name
                    if route != iface:
                        wrong_iface_count += 1
                        
                responded = len(devices)
                no_response = len(target_ips) - responded - wrong_iface_count
                if no_response < 0: no_response = 0
                
                stats = {
                    "responded": responded,
                    "wrong_iface": wrong_iface_count,
                    "no_response": no_response
                }
                
                main.enrich_devices(devices)
                
                if scan_ports:
                    main.scan_devices_ports(devices)
                
                main.save_scan(main.HISTORY_FILE, network_str, devices, stats=stats)
                
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "network": network_str, "found": len(devices)}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
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
            import scapy.all as scapy
            ifaces = scapy.get_working_ifaces()
            iface_options = ""
            for iface in ifaces:
                if iface.ip:
                    iface_options += f'<option value="{iface.name}">{iface.name} ({iface.ip})</option>'
            html = DASHBOARD_HTML.replace("<!-- IFACE_OPTIONS -->", iface_options)
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
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
