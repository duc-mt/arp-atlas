import sys
from typing import Any, List, Dict

from PySide6.QtCore import Qt, QThread, Signal, Slot
import ipaddress
import csv
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QProgressBar, QHeaderView, QCheckBox, QMessageBox, QDialog, QListWidget, QFileDialog, QComboBox, QFormLayout
)

from PySide6.QtCharts import QChart, QChartView, QPieSeries
from PySide6.QtGui import QPainter
import scapy.all as scapy
import main

class ScanWorker(QThread):
    progress = Signal(int, int, str)  # current, total, status text
    device_found = Signal(dict)       # emitted initially
    discovery_summary = Signal(int, int, int) # responded, wrong_iface, no_response
    device_updated = Signal(dict)     # emitted after port scan
    finished_scan = Signal(list)
    error = Signal(str)

    def __init__(self, start_ip: str, end_ip: str, iface: str, scan_ports: bool):
        super().__init__()
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.iface = iface
        self.scan_ports = scan_ports

    def run(self):
        try:
            import ipaddress
            start_obj = ipaddress.IPv4Address(self.start_ip)
            end_obj = ipaddress.IPv4Address(self.end_ip)
            if start_obj > end_obj:
                start_obj, end_obj = end_obj, start_obj
            
            target_ips = [str(ipaddress.ip_address(ip)) for ip in range(int(start_obj), int(end_obj) + 1)]
            
            self.progress.emit(0, 0, f"Running ARP discovery on {self.iface} for {len(target_ips)} hosts...")
            devices = main.scan_network(target_ips, iface=self.iface)
            
            wrong_iface_count = 0
            for ip in target_ips:
                route = scapy.conf.route.route(ip)[0]
                if hasattr(route, "name"): route = route.name
                if route != self.iface:
                    wrong_iface_count += 1
                    
            responded = len(devices)
            no_response = len(target_ips) - responded - wrong_iface_count
            if no_response < 0: no_response = 0
            
            self.discovery_summary.emit(responded, wrong_iface_count, no_response)
            
            if not devices:
                self.finished_scan.emit([])
                return
                
            self.progress.emit(0, len(devices), "Enriching hostnames & vendors...")
            main.enrich_devices(devices)
            
            # Emit initial discovery data
            for device in devices:
                self.device_found.emit(device)
            
            if self.scan_ports:
                self.progress.emit(0, len(devices), "Concurrent TCP Port Scanning...")
                
                def port_progress(current: int, total: int, device: Dict[str, Any]):
                    self.device_updated.emit(device)
                    self.progress.emit(current, total, f"Port scanning ({current}/{total})...")
                
                main.scan_devices_ports(devices, progress_callback=port_progress)
            
            self.progress.emit(len(devices), len(devices), "Saving history...")
            main.save_scan(main.HISTORY_FILE, f"{self.start_ip}-{self.end_ip}", devices)
            self.finished_scan.emit(devices)
            
        except Exception as e:
            self.error.emit(str(e))



class AvailableAddressesDialog(QDialog):
    def __init__(self, network_str: str, found_ips: set, parent=None):
        super().__init__(parent)
        
        try:
            if "-" in network_str:
                start_ip, end_ip = network_str.split("-")
                start_obj = ipaddress.IPv4Address(start_ip)
                end_obj = ipaddress.IPv4Address(end_ip)
                if start_obj > end_obj:
                    start_obj, end_obj = end_obj, start_obj
                all_hosts = {str(ipaddress.ip_address(ip)) for ip in range(int(start_obj), int(end_obj) + 1)}
            else:
                net = ipaddress.ip_network(network_str, strict=False)
                all_hosts = set(str(ip) for ip in net.hosts())
                
            self.available_ips = sorted(list(all_hosts - found_ips), key=lambda ip: ipaddress.ip_address(ip))
        except ValueError:
            self.available_ips = []

        self.setWindowTitle(f"Available Addresses ({len(self.available_ips)})")
        self.resize(400, 500)
        
        layout = QVBoxLayout(self)
        
        self.list_widget = QListWidget()
        self.list_widget.addItems(self.available_ips)
        layout.addWidget(self.list_widget)
        
        btn_layout = QHBoxLayout()
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        
        self.export_btn = QPushButton("Export to CSV")
        self.export_btn.clicked.connect(self.export_csv)
        
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.export_btn)
        
        layout.addLayout(btn_layout)
        
    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(self.available_ips))
        QMessageBox.information(self, "Copied", f"Copied {len(self.available_ips)} addresses to clipboard.")
        
    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "available_ips.csv", "CSV Files (*.csv)")
        if path:
            with open(path, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address"])
                for ip in self.available_ips:
                    writer.writerow([ip])
            QMessageBox.information(self, "Exported", f"Successfully exported to {path}")

class NetworkHunterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Hunter (PySide6)")
        self.resize(900, 600)
        self.worker = None
        self.row_map = {}  # Map IP to row index
        self.last_scanned_network = ""
        self.last_found_ips = set()

        self._setup_ui()

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Top Bar
        top_layout = QHBoxLayout()
        
        top_layout.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        for iface in scapy.get_working_ifaces():
            if iface.ip:
                self.iface_combo.addItem(f"{iface.name} ({iface.ip})", iface.name)
        top_layout.addWidget(self.iface_combo)
        
        top_layout.addWidget(QLabel("Start IP:"))
        self.start_ip_input = QLineEdit()
        self.start_ip_input.setPlaceholderText("192.168.1.1")
        top_layout.addWidget(self.start_ip_input)
        
        top_layout.addWidget(QLabel("End IP:"))
        self.end_ip_input = QLineEdit()
        self.end_ip_input.setPlaceholderText("192.168.1.254")
        top_layout.addWidget(self.end_ip_input)
        
        self.ports_checkbox = QCheckBox("Scan Ports")
        top_layout.addWidget(self.ports_checkbox)
        
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        top_layout.addWidget(self.scan_btn)
        
        layout.addLayout(top_layout)
        
        # Summary Bar (Hidden by default until scan starts)
        self.summary_layout = QHBoxLayout()
        self.summary_label = QLabel("Waiting for scan...")
        self.summary_bar = QProgressBar()
        self.summary_bar.setTextVisible(False)
        self.summary_bar.setFixedHeight(12)
        self.summary_layout.addWidget(self.summary_label)
        self.summary_layout.addWidget(self.summary_bar, stretch=1)
        
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.chart_view.setFixedHeight(120)
        self.chart = QChart()
        self.chart.legend().setVisible(True)
        self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignRight)
        self.chart.layout().setContentsMargins(0, 0, 0, 0)
        self.chart_view.setChart(self.chart)
        self.summary_layout.addWidget(self.chart_view)
        
        self.view_available_btn = QPushButton("View Available Addresses")
        self.view_available_btn.setEnabled(False)
        self.view_available_btn.clicked.connect(self.show_available_addresses)
        self.summary_layout.addWidget(self.view_available_btn)
        
        layout.addLayout(self.summary_layout)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "Hostname", "Open Ports", "Role"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        # Status Bar / Progress
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar, stretch=1)
        layout.addLayout(status_layout)

    def start_scan(self):
        start_ip = self.start_ip_input.text().strip()
        end_ip = self.end_ip_input.text().strip()
        iface = self.iface_combo.currentData()
        
        if not start_ip or not end_ip:
            QMessageBox.warning(self, "Input Error", "Please enter Start and End IP addresses.")
            return

        self.scan_btn.setEnabled(False)
        self.view_available_btn.setEnabled(False)
        self.table.setRowCount(0)
        self.row_map.clear()
        
        if hasattr(self, 'chart'):
            self.chart.removeAllSeries()
            
        self.worker = ScanWorker(start_ip, end_ip, iface, self.ports_checkbox.isChecked())
        self.summary_label.setText("Scanning...")
        self.summary_bar.setValue(0)
        self.summary_bar.setStyleSheet("")
        
        self.worker.progress.connect(self.update_progress)
        self.worker.discovery_summary.connect(self.update_discovery_summary)
        self.worker.device_found.connect(self.add_device_row)
        self.worker.device_updated.connect(self.update_device_row)
        self.worker.finished_scan.connect(self.scan_finished)
        self.worker.error.connect(self.scan_error)
        
        self.worker.start()

    SUMMARY_THRESHOLD_GOOD = 50.0
    SUMMARY_THRESHOLD_WARN = 10.0

    @Slot(int, int, int)
    def update_discovery_summary(self, responded: int, wrong_iface: int, no_response: int):
        total = responded + wrong_iface + no_response
        if total <= 0:
            total = 1
        pct = (responded / total) * 100
        self.summary_label.setText(f"{responded} of {total} addresses found ({pct:.1f}%)")
        self.summary_bar.setMaximum(total)
        self.summary_bar.setValue(responded)
        
        if pct >= self.SUMMARY_THRESHOLD_GOOD:
            color = "#10b981"  # Emerald
        elif pct >= self.SUMMARY_THRESHOLD_WARN:
            color = "#f59e0b"  # Amber
        else:
            color = "#ef4444"  # Red
            
        self.summary_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }} QProgressBar {{ background-color: #e2e8f0; border-radius: 2px; }}")
        
        series = QPieSeries()
        s1 = series.append("Responded", responded)
        s1.setColor(Qt.GlobalColor.green)
        s2 = series.append("Other Interface", wrong_iface)
        s2.setColor(Qt.GlobalColor.yellow)
        s3 = series.append("No Response", no_response)
        s3.setColor(Qt.GlobalColor.gray)
        self.chart.addSeries(series)

    @Slot(int, int, str)
    def update_progress(self, current: int, total: int, status: str):
        self.status_label.setText(status)
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
        else:
            self.progress_bar.setMaximum(0)  # Indeterminate mode

    @Slot(dict)
    def add_device_row(self, device: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.row_map[device["ip"]] = row
        self._populate_row(row, device)

    @Slot(dict)
    def update_device_row(self, device: dict):
        row = self.row_map.get(device["ip"])
        if row is not None:
            self._populate_row(row, device)

    def _populate_row(self, row: int, device: dict):
        self.table.setItem(row, 0, QTableWidgetItem(device.get("ip", "")))
        
        mac_text = f"{device.get('mac', '')} (Random)" if device.get("is_randomized") else device.get("mac", "")
        self.table.setItem(row, 1, QTableWidgetItem(mac_text))
        
        self.table.setItem(row, 2, QTableWidgetItem(device.get("vendor", "-") or "-"))
        self.table.setItem(row, 3, QTableWidgetItem(device.get("hostname", "-") or "-"))
        
        ports = device.get("open_ports")
        ports_text = ", ".join(map(str, ports)) if ports else "-"
        self.table.setItem(row, 4, QTableWidgetItem(ports_text))
        
        self.table.setItem(row, 5, QTableWidgetItem(device.get("role", "-").capitalize()))

    @Slot(list)
    def scan_finished(self, devices: list):
        self.scan_btn.setEnabled(True)
        self.view_available_btn.setEnabled(True)
        self.last_scanned_network = f"{self.start_ip_input.text().strip()}-{self.end_ip_input.text().strip()}"
        self.last_found_ips = {d.get("ip") for d in devices}
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(1)
        self.status_label.setText(f"Scan complete! Found {len(devices)} devices.")
        
    def show_available_addresses(self):
        dialog = AvailableAddressesDialog(self.last_scanned_network, self.last_found_ips, self)
        dialog.exec()

    @Slot(str)
    def scan_error(self, err_msg: str):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.status_label.setText("Scan failed.")
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{err_msg}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NetworkHunterGUI()
    window.show()
    sys.exit(app.exec())
