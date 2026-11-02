#!/usr/bin/env python3
"""Desktop Wi-Fi analyzer for Linux monitor-mode interfaces."""

from __future__ import annotations

import json
import hashlib
import math
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pyqtgraph as pg
from PySide6.QtCore import QThread, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from wifi_analyzer import CHANNELS_BY_BAND, signal_color

DEFAULT_INTERFACE = "wlx90de800c0cb6"
NETWORK_COLORS = (
    "#4778c7",
    "#c45b50",
    "#29927e",
    "#8a68b1",
    "#bd8737",
    "#527f8d",
    "#b45680",
    "#758d3f",
)
DARK_STYLE = """
QWidget { background: transparent; color: #e4e9f0; font-family: sans-serif; }
QMainWindow { background: #11161d; }
QFrame#card { background: #1a222c; border: 1px solid #2b3542; border-radius: 6px; }
QLabel#muted { color: #9aa7b7; }
QLabel#title { font-size: 23px; font-weight: 600; color: #f0f3f7; }
QLabel#section { font-size: 14px; font-weight: 600; color: #e4e9f0; }
QLabel#status { color: #b1bdcb; }
QComboBox, QPushButton {
    background: #222c38; border: 1px solid #394655; border-radius: 5px;
    padding: 7px 10px; color: #e4e9f0;
}
QComboBox:hover, QPushButton:hover { border-color: #6a8fbd; }
QPushButton#start { background: #376ca8; border-color: #376ca8; color: #ffffff; font-weight: 600; }
QPushButton#start:hover { background: #427bb8; }
QPushButton#start:disabled { background: #34475d; border-color: #34475d; color: #a3afbd; }
QPushButton#stop { background: #222c38; border-color: #394655; color: #e4e9f0; }
QPushButton#stop:disabled { background: #1b232d; color: #667383; border-color: #2b3542; }
QTableWidget {
    background: #1a222c; alternate-background-color: #1d2732;
    border: 0; gridline-color: #2b3542; selection-background-color: #2a3b50;
    color: #e4e9f0;
}
QHeaderView::section {
    background: #202a35; color: #aab5c2; border: 0;
    border-bottom: 1px solid #303b48; padding: 9px 8px; font-weight: 600;
}
QComboBox QAbstractItemView { background: #222c38; selection-background-color: #2a3b50; color: #e4e9f0; }
QTabWidget::pane { border: 1px solid #2b3542; background: #11161d; }
QTabBar::tab {
    background: #1a222c; color: #aab5c2; padding: 9px 16px;
    border: 1px solid #2b3542; border-bottom: 0;
}
QTabBar::tab:selected { background: #222c38; color: #f0f3f7; }
QPlainTextEdit {
    background: #151c25; color: #d7e0eb; border: 1px solid #2b3542;
    border-radius: 4px; selection-background-color: #2a3b50;
}
"""


class CaptureThread(QThread):
    event_received = Signal(dict)
    capture_error = Signal(str)

    def __init__(self, interface: str, channels: list[int], parent: QWidget | None = None):
        super().__init__(parent)
        self.interface = interface
        self.channels = channels
        self._stop_requested = threading.Event()
        self._process: subprocess.Popen[str] | None = None

    def stop(self) -> None:
        self._stop_requested.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()

    def run(self) -> None:
        worker_path = Path(__file__).with_name("capture_worker.py")
        command = [
            "sudo",
            "-n",
            sys.executable,
            "-u",
            str(worker_path),
            self.interface,
            ",".join(str(channel) for channel in self.channels),
        ]
        try:
            reported_error = False
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert self._process.stdout is not None
            for line in self._process.stdout:
                if self._stop_requested.is_set():
                    break
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self.capture_error.emit(line.strip())
                    reported_error = True
                    continue
                if event.get("type") == "error":
                    self.capture_error.emit(str(event.get("message", "Unknown error.")))
                    reported_error = True
                else:
                    self.event_received.emit(event)
            return_code = self._process.wait()
            if return_code and not self._stop_requested.is_set() and not reported_error:
                self.capture_error.emit(
                    f"Capture process exited with code {return_code}."
                )
        except OSError as error:
            self.capture_error.emit(f"Could not start capture: {error}")
        finally:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()


class SnifferThread(QThread):
    event_received = Signal(dict)
    capture_error = Signal(str)

    def __init__(self, interface: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.interface = interface
        self._stop_requested = threading.Event()
        self._process: subprocess.Popen[str] | None = None

    def stop(self) -> None:
        self._stop_requested.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()

    def run(self) -> None:
        worker_path = Path(__file__).with_name("sniffer_worker.py")
        command = [
            "sudo",
            "-n",
            sys.executable,
            "-u",
            str(worker_path),
            self.interface,
        ]
        try:
            reported_error = False
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert self._process.stdout is not None
            for line in self._process.stdout:
                if self._stop_requested.is_set():
                    break
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self.capture_error.emit(line.strip())
                    reported_error = True
                    continue
                if event.get("type") == "error":
                    self.capture_error.emit(str(event.get("message", "Unknown error.")))
                    reported_error = True
                else:
                    self.event_received.emit(event)
            return_code = self._process.wait()
            if return_code and not self._stop_requested.is_set() and not reported_error:
                self.capture_error.emit(
                    f"Packet capture process exited with code {return_code}."
                )
        except OSError as error:
            self.capture_error.emit(f"Could not start packet capture: {error}")
        finally:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()


class SignalDelegate(QWidget):
    """Paint a color-coded signal meter and its dBm value in a table cell."""

    def paintEvent(self, event: Any) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        signal = self.property("signal_dbm")
        color = QColor(signal_color(signal)) if signal is not None else QColor("#667085")
        left = 10
        base_y = self.height() - 9
        bar_width = 5
        for index, height in enumerate((7, 11, 15, 19)):
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color if signal is not None and height <= self._bar_height(signal) else QColor("#344052"))
            painter.drawRoundedRect(left + index * 8, base_y - height, bar_width, height, 2, 2)
        painter.setPen(QPen(QColor("#dce4ef")))
        label = f"{signal} dBm" if signal is not None else "N/A"
        painter.drawText(50, (self.height() + painter.fontMetrics().ascent()) // 2 - 1, label)

    @staticmethod
    def _bar_height(signal: int) -> int:
        if signal >= -50:
            return 19
        if signal >= -60:
            return 15
        if signal >= -70:
            return 11
        return 7


class NetworkCell(QWidget):
    def __init__(self, network: dict[str, Any], color: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 8, 4)
        layout.setSpacing(10)

        marker = QFrame()
        marker.setFixedSize(4, 34)
        marker.setStyleSheet(f"background:{color}; border:0; border-radius:2px;")
        layout.addWidget(marker)

        labels = QVBoxLayout()
        labels.setSpacing(2)
        ssid = QLabel(network.get("ssid") or "Hidden SSID")
        ssid.setStyleSheet("font-weight:600; color:#e4e9f0;")
        detail = QLabel(
            f"{network.get('bssid', '—')}  ·  {network.get('manufacturer') or 'Unknown manufacturer'}"
        )
        detail.setStyleSheet("font-size:11px; color:#9aa7b7;")
        labels.addWidget(ssid)
        labels.addWidget(detail)
        layout.addLayout(labels)
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Analyzer")
        self.resize(1180, 820)
        self.setMinimumSize(850, 620)
        self.networks: dict[str, dict[str, Any]] = {}
        self.capture_thread: CaptureThread | None = None
        self.sniffer_thread: SnifferThread | None = None
        self.sniffer_packets: list[dict[str, Any]] = []
        self.sniffer_started_at = 0.0
        self.sniffer_last_packet_at = 0.0
        self.sniffer_error = ""
        self.last_capture_error = ""
        self.user_stopped_capture = False
        self._build_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_views)
        self.refresh_timer.start(1000)
        self.sniffer_status_timer = QTimer(self)
        self.sniffer_status_timer.timeout.connect(self.refresh_sniffer_status)
        self.sniffer_status_timer.start(1000)

    def _build_ui(self) -> None:
        self.tabs = QTabWidget()
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(26, 22, 26, 24)
        root.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(16)
        title_block = QVBoxLayout()
        title = QLabel("WiFi Analyzer")
        title.setObjectName("title")
        subtitle = QLabel("Nearby networks and channel distribution")
        subtitle.setObjectName("muted")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        header.addLayout(title_block)
        header.addStretch()
        root.addLayout(header)

        controls = QFrame()
        controls.setObjectName("card")
        control_layout = QHBoxLayout(controls)
        control_layout.setContentsMargins(12, 10, 12, 10)
        control_layout.setSpacing(8)
        interface_label = QLabel("Interface")
        interface_label.setObjectName("muted")
        control_layout.addWidget(interface_label)
        self.interface_combo = QComboBox()
        self.interface_combo.setEditable(True)
        self.interface_combo.addItem(DEFAULT_INTERFACE)
        self.interface_combo.setMinimumWidth(210)
        control_layout.addWidget(self.interface_combo)
        self.band_combo = QComboBox()
        self.band_combo.addItems(CHANNELS_BY_BAND)
        self.band_combo.currentTextChanged.connect(self.update_band_view)
        band_label = QLabel("Band")
        band_label.setObjectName("muted")
        control_layout.addWidget(band_label)
        control_layout.addWidget(self.band_combo)
        channel_label = QLabel("Channels")
        channel_label.setObjectName("muted")
        control_layout.addWidget(channel_label)
        self.channel_combo = QComboBox()
        self.update_channel_options()
        self.channel_combo.setMinimumWidth(230)
        control_layout.addWidget(self.channel_combo)
        self.start_button = QPushButton("Start scan")
        self.start_button.setObjectName("start")
        self.start_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.start_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        control_layout.addWidget(self.stop_button)
        self.status_label = QLabel("Ready · interface must be in monitor mode")
        self.status_label.setObjectName("status")
        control_layout.addStretch()
        control_layout.addWidget(self.status_label)
        root.addWidget(controls)

        graph_card = QFrame()
        graph_card.setObjectName("card")
        graph_layout = QVBoxLayout(graph_card)
        graph_layout.setContentsMargins(14, 12, 14, 8)
        graph_header = QHBoxLayout()
        self.graph_title = QLabel()
        self.graph_title.setObjectName("section")
        graph_subtitle = QLabel("Curve color matches network · higher means stronger signal")
        graph_subtitle.setObjectName("muted")
        graph_header.addWidget(self.graph_title)
        graph_header.addStretch()
        graph_header.addWidget(graph_subtitle)
        graph_layout.addLayout(graph_header)
        self.plot = pg.PlotWidget()
        self.plot.setBackground("#1a222c")
        self.plot.showGrid(x=True, y=True, alpha=0.16)
        self.plot.setLabel("left", "Signal", units="dBm", color="#aab5c2")
        self.plot.setLabel("bottom", "Channel", color="#aab5c2")
        self.plot.setYRange(-100, -30, padding=0.02)
        self.plot.getAxis("left").setTextPen("#aab5c2")
        self.plot.getAxis("bottom").setTextPen("#aab5c2")
        self.plot.getAxis("left").setPen("#465363")
        self.plot.getAxis("bottom").setPen("#465363")
        self.plot.setMinimumHeight(240)
        graph_layout.addWidget(self.plot)
        root.addWidget(graph_card, 4)

        table_card = QFrame()
        table_card.setObjectName("card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(14, 12, 14, 10)
        table_header = QHBoxLayout()
        table_title = QLabel("Detected networks")
        table_title.setObjectName("section")
        self.table_count = QLabel("0 networks")
        self.table_count.setObjectName("muted")
        table_header.addWidget(table_title)
        table_header.addStretch()
        table_header.addWidget(self.table_count)
        table_layout.addLayout(table_header)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Network", "Channel", "Security", "Signal"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(54)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header_view.resizeSection(1, 125)
        header_view.resizeSection(2, 145)
        header_view.resizeSection(3, 120)
        table_layout.addWidget(self.table)
        root.addWidget(table_card, 5)

        footer = QLabel(
            "Signal: green = strong · yellow = fair · red = weak"
            "     ·     The graph shows observed networks, not actual channel utilization"
        )
        footer.setObjectName("muted")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(footer)
        self.tabs.addTab(central, "WiFi Analyzer")
        self._build_sniffer_ui()
        self.setCentralWidget(self.tabs)
        self.update_band_view()

    def update_channel_options(self) -> None:
        channels = CHANNELS_BY_BAND[self.band_combo.currentText()]
        self.channel_combo.clear()
        self.channel_combo.addItem("All channels", None)
        for channel in channels:
            self.channel_combo.addItem(f"Channel {channel}", channel)

    def update_band_view(self) -> None:
        band = self.band_combo.currentText()
        channels = CHANNELS_BY_BAND[band]
        self.update_channel_options()
        self.graph_title.setText(f"Channel graph · {band}")
        self.plot.setXRange(channels[0], channels[-1], padding=0.02)
        self.plot.getAxis("bottom").setTicks(
            [[(channel, str(channel)) for channel in channels]]
        )
        self.refresh_views()

    def _build_sniffer_ui(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(26, 22, 26, 24)
        layout.setSpacing(14)

        heading = QLabel("Network Packet Sniffer")
        heading.setObjectName("title")
        description = QLabel(
            "Live link-layer capture with manually parsed Ethernet, 802.11, IP, TCP and UDP headers"
        )
        description.setObjectName("muted")
        layout.addWidget(heading)
        layout.addWidget(description)

        controls = QFrame()
        controls.setObjectName("card")
        control_layout = QHBoxLayout(controls)
        control_layout.setContentsMargins(12, 10, 12, 10)
        control_layout.setSpacing(8)
        interface_label = QLabel("Interface")
        interface_label.setObjectName("muted")
        control_layout.addWidget(interface_label)
        self.sniffer_interface_combo = QComboBox()
        self.sniffer_interface_combo.setEditable(True)
        self.sniffer_interface_combo.addItems([DEFAULT_INTERFACE, "wlo1"])
        self.sniffer_interface_combo.setMinimumWidth(220)
        control_layout.addWidget(self.sniffer_interface_combo)
        self.sniffer_start_button = QPushButton("Start capture")
        self.sniffer_start_button.setObjectName("start")
        self.sniffer_start_button.clicked.connect(self.start_sniffer)
        control_layout.addWidget(self.sniffer_start_button)
        self.sniffer_stop_button = QPushButton("Stop")
        self.sniffer_stop_button.setObjectName("stop")
        self.sniffer_stop_button.setEnabled(False)
        self.sniffer_stop_button.clicked.connect(self.stop_sniffer)
        control_layout.addWidget(self.sniffer_stop_button)
        self.sniffer_clear_button = QPushButton("Clear")
        self.sniffer_clear_button.clicked.connect(self.clear_sniffer_packets)
        control_layout.addWidget(self.sniffer_clear_button)
        control_layout.addStretch()
        self.sniffer_status_label = QLabel("Ready")
        self.sniffer_status_label.setObjectName("status")
        control_layout.addWidget(self.sniffer_status_label)
        layout.addWidget(controls)

        packet_card = QFrame()
        packet_card.setObjectName("card")
        packet_layout = QVBoxLayout(packet_card)
        packet_layout.setContentsMargins(14, 12, 14, 12)
        packet_heading = QHBoxLayout()
        packet_title = QLabel("Captured packets")
        packet_title.setObjectName("section")
        self.packet_count_label = QLabel("0 packets")
        self.packet_count_label.setObjectName("muted")
        packet_heading.addWidget(packet_title)
        packet_heading.addStretch()
        packet_heading.addWidget(self.packet_count_label)
        packet_layout.addLayout(packet_heading)

        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(
            ["Time", "Mode", "Source", "Destination", "Protocol", "Summary"]
        )
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setShowGrid(False)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(32)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        packet_header = self.packet_table.horizontalHeader()
        packet_header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 95), (1, 85), (2, 185), (3, 185), (4, 95)):
            packet_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed)
            packet_header.resizeSection(column, width)
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        packet_layout.addWidget(self.packet_table, 3)

        details_heading = QLabel("Packet details")
        details_heading.setObjectName("section")
        packet_layout.addWidget(details_heading)
        self.packet_details = QPlainTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setPlaceholderText("Select a packet to inspect its parsed headers and payload.")
        self.packet_details.setMaximumBlockCount(3000)
        self.packet_details.setMinimumHeight(190)
        packet_layout.addWidget(self.packet_details, 2)
        layout.addWidget(packet_card, 1)

        note = QLabel(
            "Monitor mode shows 802.11 headers; encrypted Wi-Fi data cannot be decoded here. "
            "Managed mode shows Ethernet headers after Wi-Fi decapsulation."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.tabs.addTab(page, "Packet Sniffer")

    def start_scan(self) -> None:
        interface = self.interface_combo.currentText().strip()
        if not interface:
            self._show_error("Enter a Wi-Fi interface name.")
            return
        if (
            self.sniffer_thread
            and self.sniffer_thread.isRunning()
            and self.sniffer_thread.interface == interface
        ):
            self._show_error("Stop packet capture on this interface before starting the Wi-Fi scan.")
            return
        if not self._check_capture_privileges():
            return
        try:
            info = subprocess.run(
                ["iw", "dev", interface, "info"],
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
        except (OSError, subprocess.SubprocessError) as error:
            self._show_error(f"Could not check interface {interface}:\n{error}")
            return
        if "type monitor" not in info:
            self._show_error(
                f"Interface {interface} is not in monitor mode.\n\n"
                "Check it with `iw dev` and set the USB adapter to monitor mode."
            )
            return

        selected_channel = self.channel_combo.currentData()
        channels = (
            list(CHANNELS_BY_BAND[self.band_combo.currentText()])
            if selected_channel is None
            else [int(selected_channel)]
        )
        self.networks.clear()
        self.refresh_views()
        self.last_capture_error = ""
        self.user_stopped_capture = False
        self.capture_thread = CaptureThread(interface, channels, self)
        self.capture_thread.event_received.connect(self.handle_capture_event)
        self.capture_thread.capture_error.connect(self.handle_capture_error)
        self.capture_thread.finished.connect(self.capture_finished)
        self.capture_thread.start()
        self.interface_combo.setEnabled(False)
        self.band_combo.setEnabled(False)
        self.channel_combo.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Starting capture…")

    def start_sniffer(self) -> None:
        interface = self.sniffer_interface_combo.currentText().strip()
        if not interface:
            self._show_error("Enter a Wi-Fi interface name.")
            return
        if (
            self.capture_thread
            and self.capture_thread.isRunning()
            and self.capture_thread.interface == interface
        ):
            self._show_error("Stop the WiFi Analyzer scan on this interface before packet capture.")
            return
        if not self._check_capture_privileges():
            return
        try:
            info = subprocess.run(
                ["iw", "dev", interface, "info"],
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
        except (OSError, subprocess.SubprocessError) as error:
            self._show_error(f"Could not check interface {interface}:\n{error}")
            return
        interface_mode = next(
            (
                line.strip().partition(" ")[2]
                for line in info.splitlines()
                if line.strip().startswith("type ")
            ),
            "",
        )
        if interface_mode not in ("managed", "monitor"):
            self._show_error(
                f"Interface {interface} has unsupported mode '{interface_mode or 'unknown'}'. "
                "Use managed or monitor mode."
            )
            return

        self.sniffer_packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.packet_count_label.setText("0 packets")
        self.sniffer_error = ""
        self.sniffer_started_at = time.monotonic()
        self.sniffer_last_packet_at = 0.0
        self.sniffer_thread = SnifferThread(interface, self)
        self.sniffer_thread.event_received.connect(self.handle_sniffer_event)
        self.sniffer_thread.capture_error.connect(self.handle_sniffer_error)
        self.sniffer_thread.finished.connect(self.sniffer_finished)
        self.sniffer_thread.start()
        self.sniffer_interface_combo.setEnabled(False)
        self.sniffer_start_button.setEnabled(False)
        self.sniffer_stop_button.setEnabled(True)
        self.sniffer_status_label.setText("Starting capture…")

    def stop_sniffer(self) -> None:
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_status_label.setText("Stopping capture…")
            self.sniffer_stop_button.setEnabled(False)
            self.sniffer_thread.stop()

    def handle_sniffer_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "ready":
            self.sniffer_status_label.setText(
                f"Capturing on {event.get('interface')} · {event.get('mode')} mode"
            )
            self.sniffer_started_at = time.monotonic()
        elif event.get("type") == "packet":
            self.add_sniffer_packet(event)

    def handle_sniffer_error(self, message: str) -> None:
        self.sniffer_error = message
        self.sniffer_status_label.setText(f"Capture error: {message}")

    def sniffer_finished(self) -> None:
        self.sniffer_interface_combo.setEnabled(True)
        self.sniffer_start_button.setEnabled(True)
        self.sniffer_stop_button.setEnabled(False)
        if self.sniffer_error:
            QMessageBox.warning(
                self,
                "Packet capture failed",
                f"{self.sniffer_error}\n\n"
                "Raw packet capture requires administrator privileges. Open a terminal, "
                "run `sudo -v`, then start capture again. The authorization expires "
                "after a period of inactivity.",
            )
        elif self.sniffer_status_label.text().startswith("Stopping"):
            self.sniffer_status_label.setText("Capture stopped.")
        elif self.sniffer_status_label.text().startswith("Starting"):
            self.sniffer_status_label.setText("Capture ended.")
        self.sniffer_thread = None

    def add_sniffer_packet(self, packet: dict[str, Any]) -> None:
        self.sniffer_last_packet_at = time.monotonic()
        self.sniffer_packets.append(packet)
        if len(self.sniffer_packets) > 2000:
            self.sniffer_packets.pop(0)
            self.packet_table.removeRow(0)

        ip_header = packet.get("ip") or {}
        transport = packet.get("transport") or {}
        link = packet.get("link") or {}
        if ip_header:
            source = ip_header.get("source_ip", "—")
            destination = ip_header.get("destination_ip", "—")
            if transport:
                source = f"{source}:{transport.get('source_port', '?')}"
                destination = f"{destination}:{transport.get('destination_port', '?')}"
        else:
            source = link.get("source_mac") or "—"
            destination = link.get("destination_mac") or "—"
        timestamp = time.strftime("%H:%M:%S", time.localtime(packet.get("timestamp", time.time())))
        values = (
            timestamp,
            str(packet.get("mode", "—")).title(),
            source,
            destination,
            packet.get("protocol", "—"),
            packet.get("summary", packet.get("parse_note", "—")),
        )
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if column == 5:
                item.setData(Qt.ItemDataRole.UserRole, packet)
            self.packet_table.setItem(row, column, item)
        self.packet_count_label.setText(f"{len(self.sniffer_packets)} packets")
        self.packet_table.scrollToBottom()

    def show_packet_details(self) -> None:
        row = self.packet_table.currentRow()
        item = self.packet_table.item(row, 5) if row >= 0 else None
        packet = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.packet_details.setPlainText(
            json.dumps(packet, indent=2, ensure_ascii=True) if packet else ""
        )

    def clear_sniffer_packets(self) -> None:
        self.sniffer_packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.packet_count_label.setText("0 packets")

    def refresh_sniffer_status(self) -> None:
        if not self.sniffer_thread or not self.sniffer_thread.isRunning():
            return
        if self.sniffer_error:
            return
        now = time.monotonic()
        last_packet = self.sniffer_last_packet_at or self.sniffer_started_at
        if last_packet and now - last_packet >= 5:
            mode = "monitor" if "monitor" in self.sniffer_status_label.text().lower() else "managed"
            self.sniffer_status_label.setText(
                f"Capture active · no packets received yet on this {mode} interface"
            )

    def _check_capture_privileges(self) -> bool:
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError) as error:
            self._show_error(f"Could not verify capture permissions:\n{error}")
            return False
        if result.returncode == 0:
            return True
        self._show_error(
            "Capture needs administrator privileges. Open a terminal, run "
            "`sudo -v`, then start capture again. If the authorization has "
            "expired, run `sudo -v` again."
        )
        return False

    def stop_scan(self) -> None:
        if self.capture_thread and self.capture_thread.isRunning():
            self.user_stopped_capture = True
            self.status_label.setText("Stopping capture…")
            self.stop_button.setEnabled(False)
            self.capture_thread.stop()

    def handle_capture_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "ready":
            self.status_label.setText("Scanning · passive capture")
        elif event_type == "channel":
            self.status_label.setText(
                f"Scanning {self.band_combo.currentText()} · channel {event.get('channel', '—')}"
            )
        elif event_type == "network":
            bssid = event.get("bssid")
            if bssid:
                event["last_seen"] = time.strftime("%H:%M:%S")
                self.networks[str(bssid)] = event
        elif event_type == "warning":
            self.status_label.setText(f"Warning: {event.get('message', '')}")

    def handle_capture_error(self, message: str) -> None:
        self.last_capture_error = message
        self.status_label.setText(f"Capture error: {message}")

    def capture_finished(self) -> None:
        self.interface_combo.setEnabled(True)
        self.band_combo.setEnabled(True)
        self.channel_combo.setEnabled(True)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.last_capture_error:
            self.status_label.setText("Capture stopped with an error.")
            QMessageBox.warning(
                self,
                "Wi-Fi capture failed",
                f"{self.last_capture_error}\n\n"
                "For permissions, open a terminal and run `sudo -v`, then "
                "start scanning again. Keep the graphical application running "
                "as your normal user.",
            )
        elif self.user_stopped_capture:
            self.status_label.setText("Scan stopped.")
        else:
            self.status_label.setText("Capture ended.")
        self.capture_thread = None

    def refresh_views(self) -> None:
        now = time.time()
        visible = [
            network for network in self.networks.values()
            if now - float(network.get("timestamp", now)) <= 20
        ]
        self.networks = {
            str(network["bssid"]): network
            for network in visible
            if network.get("bssid")
        }
        selected_channels = set(CHANNELS_BY_BAND[self.band_combo.currentText()])
        visible = [
            network for network in visible
            if int(network.get("channel") or 0) in selected_channels
        ]
        visible.sort(
            key=lambda network: (
                network.get("signal_dbm") is not None,
                network.get("signal_dbm") or -100,
            ),
            reverse=True,
        )
        count_label = "network" if len(visible) == 1 else "networks"
        self.table_count.setText(f"{len(visible)} {count_label} · live")
        self._update_table(visible)
        self._update_plot(visible)

    def _update_table(self, networks: list[dict[str, Any]]) -> None:
        self.table.setRowCount(len(networks))
        for row, network in enumerate(networks):
            channel = network.get("channel")
            frequency = network.get("frequency_mhz")
            channel_text = f"Ch {channel}  ·  {frequency} MHz" if channel and frequency else "—"
            color = self._network_color(str(network.get("bssid", "")))
            self.table.setCellWidget(row, 0, NetworkCell(network, color, self.table))
            channel_item = QTableWidgetItem(channel_text)
            channel_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 1, channel_item)
            security_item = QTableWidgetItem(network.get("security") or "Unknown")
            security_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 2, security_item)
            meter = SignalDelegate(self.table)
            meter.setProperty("signal_dbm", network.get("signal_dbm"))
            self.table.setCellWidget(row, 3, meter)
        self.table.setSortingEnabled(False)

    @staticmethod
    def _network_color(bssid: str) -> str:
        digest = hashlib.blake2b(bssid.encode("utf-8"), digest_size=1).digest()[0]
        return NETWORK_COLORS[digest % len(NETWORK_COLORS)]

    def _update_plot(self, networks: list[dict[str, Any]]) -> None:
        self.plot.clear()
        channels = CHANNELS_BY_BAND[self.band_combo.currentText()]
        lower_limit, upper_limit = channels[0], channels[-1]
        spread = 1.35 if self.band_combo.currentText() == "2.4 GHz" else 3.0
        for network in networks:
            channel = int(network.get("channel") or 0)
            signal = network.get("signal_dbm")
            if channel not in channels or signal is None:
                continue
            lower = max(float(lower_limit), channel - spread * 2)
            upper = min(float(upper_limit), channel + spread * 2)
            steps = 60
            xs = [lower + (upper - lower) * index / steps for index in range(steps + 1)]
            ys = [
                -100 + (max(-100, min(-25, signal)) + 100)
                * math.exp(-((x - channel) ** 2) / (2 * spread**2))
                for x in xs
            ]
            color = QColor(self._network_color(str(network.get("bssid", ""))))
            self.plot.plot(
                xs,
                ys,
                pen=pg.mkPen(color, width=2.2),
                fillLevel=-100,
                brush=pg.mkBrush(color.red(), color.green(), color.blue(), 24),
            )
        if not networks:
            self.plot.setTitle("Start scanning to see nearby networks", color="#9aa7b7")
        else:
            self.plot.setTitle("", color="#758294")

    def _show_error(self, message: str) -> None:
        QMessageBox.warning(self, "WiFi Analyzer", message)

    def closeEvent(self, event: Any) -> None:
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
        event.accept()


def main() -> int:
    os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")
    app = QApplication(sys.argv)
    app.setApplicationName("Network Analyzer")
    app.setStyleSheet(DARK_STYLE)
    pg.setConfigOptions(antialias=True)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
