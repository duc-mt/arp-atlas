import http.server
import json
import os
import socketserver
import threading
from typing import Any

with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), encoding="utf-8") as f:
    DASHBOARD_HTML = f.read()

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
                
                responded_ips = {d.get("ip") for d in devices}
                wrong_iface_count = 0
                for ip in target_ips:
                    if ip in responded_ips:
                        continue
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

class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def run_dashboard(port: int = 8080) -> None:
    print(f"Starting web dashboard at http://localhost:{port}")
    with ReuseTCPServer(("127.0.0.1", port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard.")
