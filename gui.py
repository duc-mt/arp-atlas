import sys
from typing import Any, List, Dict

from PySide6.QtCore import Qt, QThread, Signal, Slot
import ipaddress
import csv
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QProgressBar, QHeaderView, QCheckBox, QMessageBox, QDialog, QListWidget, QFileDialog
)

import main

class ScanWorker(QThread):
    progress = Signal(int, int, str)  # current, total, status text
    device_found = Signal(dict)       # emitted initially
    discovery_summary = Signal(int, int) # found, total
    device_updated = Signal(dict)     # emitted after port scan
    finished_scan = Signal(list)
    error = Signal(str)

    def __init__(self, network: str, scan_ports: bool):
        super().__init__()
        self.network = network
        self.scan_ports = scan_ports

    def run(self):
        try:
            self.progress.emit(0, 0, "Validating network...")
            valid_network = main.validate_network(self.network)
            
            self.progress.emit(0, 0, f"Running ARP discovery on {valid_network}...")
            devices = main.scan_network(valid_network)
            
            import ipaddress
            net_obj = ipaddress.ip_network(valid_network, strict=False)
            total_ips = net_obj.num_addresses
            total_hosts = total_ips - 2 if net_obj.version == 4 and net_obj.prefixlen <= 30 else total_ips
            self.discovery_summary.emit(len(devices), total_hosts)
            
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
            main.save_scan(main.HISTORY_FILE, valid_network, devices)
            self.finished_scan.emit(devices)
            
        except Exception as e:
            self.error.emit(str(e))



class AvailableAddressesDialog(QDialog):
    def __init__(self, network_str: str, found_ips: set, parent=None):
        super().__init__(parent)
        
        try:
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
        top_layout.addWidget(QLabel("Network:"))
        
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("e.g. 192.168.1.0/24")
        top_layout.addWidget(self.network_input)
        
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
        network = self.network_input.text().strip()
        if not network:
            QMessageBox.warning(self, "Input Error", "Please enter a network address.")
            return

        self.scan_btn.setEnabled(False)
        self.view_available_btn.setEnabled(False)
        self.table.setRowCount(0)
        self.row_map.clear()
        
        self.worker = ScanWorker(network, self.ports_checkbox.isChecked())
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

    @Slot(int, int)
    def update_discovery_summary(self, found: int, total: int):
        if total <= 0:
            total = 1
        pct = (found / total) * 100
        self.summary_label.setText(f"{found} of {total} addresses found ({pct:.1f}%)")
        self.summary_bar.setMaximum(total)
        self.summary_bar.setValue(found)
        
        if pct >= self.SUMMARY_THRESHOLD_GOOD:
            color = "#10b981"  # Emerald
        elif pct >= self.SUMMARY_THRESHOLD_WARN:
            color = "#f59e0b"  # Amber
        else:
            color = "#ef4444"  # Red
            
        self.summary_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }} QProgressBar {{ background-color: #e2e8f0; border-radius: 2px; }}")

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
        self.last_scanned_network = self.network_input.text().strip()
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
