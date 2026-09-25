from __future__ import annotations

import os
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl, QProcess, QProcessEnvironment
from PySide6.QtGui import QColor, QDesktopServices, QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableView,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QApplication,
)

from . import pci, theme, topology, trace

PAIR_ROLE = Qt.ItemDataRole.UserRole + 1
COLUMNS = ["Timestamp", "Direction", "Type", "Requester", "Completer", "Tag", "Length", "Addr", "Payload", "Match"]


def _items(row: dict) -> list[QStandardItem]:
    cells = []
    for key in ("ts", "direction", "type", "requester", "completer", "tag", "length", "addr", "payload", "match"):
        item = QStandardItem(str(row.get(key, "")))
        if key == "match":
            item.setData(int(row.get("pair", -1)), PAIR_ROLE)
        cells.append(item)
    return cells


class FabricCard(QFrame):
    def __init__(self, title: str, sub: str, body: str, accent: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("fabricCard")
        self.setStyleSheet(
            f"QFrame#fabricCard {{ background: #111827; border: 1px solid {accent}; border-radius: 6px; }}"
            "QLabel { color: #e7ebf3; background: transparent; }"
            "QLabel#cardSub { color: #94a3b8; font-size: 11px; }"
        )
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.setMinimumHeight(72)
        self.setMaximumHeight(92)
        box = QVBoxLayout(self)
        box.setContentsMargins(10, 8, 10, 8)
        box.setSpacing(2)
        title_lab = QLabel(f"[ {title} ]")
        title_lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lab.setStyleSheet("font-weight: 700;")
        sub_lab = QLabel(sub)
        sub_lab.setObjectName("cardSub")
        sub_lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_lab.setWordWrap(True)
        body_lab = QLabel(body)
        body_lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(title_lab)
        box.addWidget(sub_lab)
        box.addWidget(body_lab)


class FabricDiagram(QScrollArea):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._canvas = QWidget()
        self._canvas.setObjectName("fabricCanvas")
        self._canvas.setStyleSheet("QWidget#fabricCanvas { background: #0f1117; }")
        self._layout = QVBoxLayout(self._canvas)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.setSpacing(8)
        self.setWidget(self._canvas)

    def set_topology(self, topo: dict) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        rc_label = "CPU Complex"
        bus_label = "PCIe Bus 00"
        rp: list[FabricCard] = []
        sw: list[FabricCard] = []
        dp: list[FabricCard] = []
        ep: list[FabricCard] = []
        for rc in topo.get("root_complexes", []):
            rc_label = rc.get("label") or rc_label
            if rc.get("root_bus"):
                bus_label = f"PCIe Bus {rc['root_bus']}"
            for i, port in enumerate(rc.get("root_ports", [])):
                if isinstance(port, str):
                    rp.append(FabricCard(f"rp{i + 1}", port, "root port", "#60a5fa"))
                else:
                    sub = port.get("bdf") or port.get("addr") or ""
                    if port.get("secondary_bus"):
                        sub += f"  Bus {port['secondary_bus']}"
                    rp.append(FabricCard(port.get("id", f"rp{i + 1}"), sub, port.get("label", ""), "#60a5fa"))
        for item in topo.get("switches", []):
            name = item.get("name", "switch")
            sw.append(FabricCard(f"{name}_up", item.get("upstream_port", ""), item.get("parent", ""), "#94a3b8"))
            for d, bdf in enumerate(item.get("downstream_ports", [])):
                dp.append(FabricCard(f"{name} dp{d}", bdf, "downstream", "#7dd3fc"))
        for item in topo.get("endpoints", []):
            kind = str(item.get("type", "")).upper()
            if "GPU" in kind or "ACCEL" in kind:
                accent = "#3b82f6"
            elif "NVME" in kind or "STOR" in kind:
                accent = "#10b981"
            elif "NIC" in kind or "ETH" in kind or "NET" in kind:
                accent = "#f59e0b"
            else:
                accent = "#64748b"
            ep.append(FabricCard(item.get("display") or item.get("label") or "ep",
                                 item.get("bdf") or kind, item.get("label", ""), accent))

        def heading(text: str, size: int = 16) -> QLabel:
            lab = QLabel(text)
            lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lab.setStyleSheet(f"color:#e7ebf3;font-weight:700;font-size:{size}px;background:transparent;")
            return lab

        self._layout.addWidget(heading(f"[ {rc_label} ]", 18))
        self._layout.addWidget(heading(f"[ {bus_label} ]", 14))
        sub = QLabel(topo.get("topology_name", ""))
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color:#94a3b8;font-size:12px;background:transparent;")
        self._layout.addWidget(sub)
        for cards in (rp, sw, dp, ep):
            if not cards:
                continue
            grid = QGridLayout()
            grid.setContentsMargins(0, 4, 0, 4)
            grid.setHorizontalSpacing(8)
            grid.setVerticalSpacing(8)
            for i, card in enumerate(cards):
                grid.addWidget(card, i // 4, i % 4)
                grid.setColumnStretch(i % 4, 1)
            for col in range(4):
                grid.setColumnStretch(col, 1)
            row = QWidget()
            row.setLayout(grid)
            self._layout.addWidget(row)
        self._layout.addStretch(1)


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "scripts" / "run_linux_ai_topology.sh").exists():
            return parent
    return Path.cwd()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.dark_mode = False
        self.rows: list[dict] = []
        self.topology = topology.golden_topology()
        self.run_mode = "zephyr"
        self.live_path = ""
        self.live_seen: set[str] = set()
        self.live_proc: QProcess | None = None
        self.live_timer: QTimer | None = None
        self.suppress_exit = False
        self.last_perf = {"devices": 0, "txns": 0, "ns": 0, "rate": 0.0}
        self.emu: QDialog | None = None
        self.topo_view: FabricDiagram | None = None
        self.topo_badge: QLabel | None = None
        self.mode_combo: QComboBox | None = None
        self.run_button: QPushButton | None = None
        self.perf_label: QLabel | None = None
        self.fabric_box: QGroupBox | None = None
        self.device_bdf = "0000:00:03.0"
        self.backend_name = "pci"

        central = QWidget(self)
        layout = QVBoxLayout(central)
        toolbar = QHBoxLayout()
        filters = QHBoxLayout()

        self.open_btn = QPushButton("Open trace")
        self.open_btn.setObjectName("openButton")
        self.save_btn = QPushButton("Save trace")
        self.report_btn = QPushButton("Export report")
        self.enum_btn = QPushButton("Enumerate PCI")
        self.ai_btn = QPushButton("AI PCIe Emulator")
        self.theme_btn = QPushButton("Dark")
        self.theme_btn.setObjectName("themeButton")
        toolbar.addWidget(self.open_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.report_btn)
        toolbar.addWidget(self.enum_btn)
        toolbar.addWidget(self.ai_btn)
        toolbar.addWidget(self.theme_btn)
        toolbar.addStretch()

        self.type_filter = QComboBox()
        self.type_filter.addItems(["All types", "CfgRd", "CfgWr", "MemRd", "MemWr", "Cpl"])
        self.dir_filter = QComboBox()
        self.dir_filter.addItems(["All directions", "TX", "RX"])
        self.analysis_filter = QComboBox()
        self.analysis_filter.addItems(["All packets", "Unmatched", "Matched pairs"])
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search type, BDF, tag, address, or payload")
        filters.addWidget(QLabel("Type:"))
        filters.addWidget(self.type_filter)
        filters.addWidget(QLabel("Direction:"))
        filters.addWidget(self.dir_filter)
        filters.addWidget(QLabel("Analysis:"))
        filters.addWidget(self.analysis_filter)
        filters.addWidget(self.search, 1)

        stats = QHBoxLayout()
        self.total_label = QLabel("Total: 0")
        self.tx_label = QLabel("TX: 0")
        self.rx_label = QLabel("RX: 0")
        self.visible_label = QLabel("Visible: 0")
        self.unmatched_label = QLabel("Unmatched: 0")
        for lab in (self.total_label, self.tx_label, self.rx_label, self.visible_label, self.unmatched_label):
            lab.setObjectName("summaryCard")
            lab.setFrameShape(QFrame.Shape.StyledPanel)
            lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stats.addWidget(lab)

        legend = QLabel("Match: #N = request/completion pair   ·   complete = QEMU one-line cfg access   ·   unmatched = missing Cpl   ·   — = no pair expected")
        legend.setObjectName("statusLabel")
        legend.setWordWrap(True)

        self.model = QStandardItemModel(self)
        self.model.setHorizontalHeaderLabels(COLUMNS)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(False)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.decode = QTreeWidget()
        self.decode.setHeaderLabels(["Field", "Value"])
        self.decode.setColumnWidth(0, 220)
        self.decode.setAlternatingRowColors(True)
        details_split = QSplitter(Qt.Orientation.Vertical)
        details_split.addWidget(self.details)
        details_split.addWidget(self.decode)
        details_split.setStretchFactor(0, 2)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(details_split)
        splitter.setStretchFactor(0, 3)

        self.status = QLabel("No trace loaded")
        self.status.setObjectName("statusLabel")

        layout.addLayout(toolbar)
        layout.addLayout(filters)
        layout.addLayout(stats)
        layout.addWidget(legend)
        layout.addWidget(splitter)
        layout.addWidget(self.status)
        self.setCentralWidget(central)
        self.setWindowTitle("pcieshark")
        self._fit(self, 1.0)
        self._apply_theme()

        self.open_btn.clicked.connect(self.open_trace)
        self.save_btn.clicked.connect(self.save_trace)
        self.report_btn.clicked.connect(self.export_report)
        self.enum_btn.clicked.connect(self.enumerate_pci)
        self.ai_btn.clicked.connect(self.open_emulator)
        self.theme_btn.clicked.connect(self._toggle_theme)
        self.type_filter.currentTextChanged.connect(self.apply_filter)
        self.dir_filter.currentTextChanged.connect(self.apply_filter)
        self.analysis_filter.currentTextChanged.connect(self.apply_filter)
        self.search.textChanged.connect(self.apply_filter)
        self.table.selectionModel().currentRowChanged.connect(lambda *_: self.show_details())
        self.table.doubleClicked.connect(self.jump_pair)

    def _fit(self, widget: QWidget, scale: float) -> None:
        screen = widget.screen() or QApplication.primaryScreen()
        if not screen:
            return
        avail = screen.availableGeometry()
        margin = 0 if scale >= 0.99 else 16
        width = min(max(720, int(avail.width() * scale) - margin), avail.width() - margin)
        height = min(max(520, int(avail.height() * scale) - margin), avail.height() - margin)
        widget.setGeometry(avail.x() + (avail.width() - width) // 2, avail.y() + (avail.height() - height) // 2, width, height)

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.DARK if self.dark_mode else theme.LIGHT)
        self.theme_btn.setText("Light" if self.dark_mode else "Dark")
        self.color_rows()

    def _toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    def _set_rows(self, rows: list[dict]) -> None:
        self.rows = rows
        self.model.removeRows(0, self.model.rowCount())
        for row in rows:
            self.model.appendRow(_items(row))
        self.apply_filter()
        if self.model.rowCount():
            self.table.selectRow(0)

    def load_trace(self, path: str) -> None:
        try:
            rows = trace.load_rows(path)
        except OSError as exc:
            QMessageBox.critical(self, "Open failed", str(exc))
            return
        if not rows:
            QMessageBox.warning(self, "Invalid trace", "The trace file is empty or has no TLP rows.")
            return
        self._set_rows(rows)
        self.status.setText(f"Loaded {len(rows)} TLP entries from {path}")

    def open_trace(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open PCIe trace", "", "Trace files (*.csv *.log *.txt *.pcie);;All files (*)")
        if path:
            self.load_trace(path)

    def save_trace(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Save trace", "There is no trace to save yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PCIe trace", "pcie_trace.csv", "CSV traces (*.csv);;QEMU logs (*.log *.txt)")
        if not path:
            return
        try:
            trace.save_csv(path, self.rows)
        except OSError as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.status.setText(f"Saved {len(self.rows)} TLP entries to {path}")

    def export_report(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Export report", "There is no trace to report yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export analysis report", "pcieshark_report.html", "HTML report (*.html)")
        if not path:
            return
        trace.export_report(path, self.rows, self.topology.get("topology_name", ""))
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        self.status.setText(f"Exported analysis report to {path}")

    def apply_filter(self) -> None:
        typ = self.type_filter.currentText()
        direction = self.dir_filter.currentText()
        analysis = self.analysis_filter.currentText()
        text = self.search.text().strip().lower()
        visible = 0
        for row in range(self.model.rowCount()):
            show = True
            row_type = self.model.index(row, 2).data()
            row_dir = self.model.index(row, 1).data()
            match = self.model.index(row, 9).data()
            pair = self.model.item(row, 9).data(PAIR_ROLE) if self.model.item(row, 9) else -1
            if typ != "All types" and row_type != typ:
                show = False
            if direction != "All directions" and row_dir != direction:
                show = False
            if analysis == "Unmatched" and match != "unmatched":
                show = False
            if analysis == "Matched pairs" and int(pair) < 0:
                show = False
            if text:
                hay = " ".join(str(self.model.index(row, c).data() or "") for c in range(self.model.columnCount())).lower()
                if text not in hay:
                    show = False
            self.table.setRowHidden(row, not show)
            if show:
                visible += 1
        self.color_rows()
        self.show_details()
        self._update_stats(visible)

    def _update_stats(self, visible: int) -> None:
        tx = sum(1 for r in self.rows if r["direction"] == "TX")
        rx = sum(1 for r in self.rows if r["direction"] == "RX")
        unmatched = sum(1 for r in self.rows if r["match"] == "unmatched")
        req = sum(1 for r in self.rows if str(r["type"]) in trace.REQUEST_TYPES)
        cpl = sum(1 for r in self.rows if str(r["type"]) in trace.COMPLETION_TYPES)
        self.total_label.setText(f"Total: {len(self.rows)}")
        self.tx_label.setText(f"TX: {tx}")
        self.rx_label.setText(f"RX: {rx}")
        self.visible_label.setText(f"Visible: {visible}")
        self.unmatched_label.setText(f"Unmatched: {unmatched}  ·  CfgRd/MemRd {req}  ·  Cpl {cpl}")

    def color_rows(self) -> None:
        current = self.table.currentIndex().row()
        for row in range(self.model.rowCount()):
            direction = str(self.model.index(row, 1).data())
            typ = str(self.model.index(row, 2).data())
            match = str(self.model.index(row, 9).data())
            if row == current:
                bg, fg = (QColor("#2a68bf"), QColor("#ffffff")) if self.dark_mode else (QColor("#dfeaff"), QColor("#0f172a"))
            elif self.dark_mode:
                bg, fg = QColor("#1a2d3d"), QColor("#e5edf7")
                colors = {"CfgRd": "#224b70", "CfgWr": "#5a3240", "MemRd": "#1e3d5a", "MemWr": "#594d25", "Cpl": "#2e3459"}
                bg = QColor(colors.get(typ, "#1d3a4f" if direction == "TX" else "#1f382e"))
                if match == "unmatched":
                    bg = QColor("#5b2a2a")
            else:
                bg, fg = QColor("#f4f6fb"), QColor("#1f2328")
                colors = {"CfgRd": "#eaf1ff", "CfgWr": "#fff0ef", "MemRd": "#eef3ff", "MemWr": "#fff8eb", "Cpl": "#f2f0ff"}
                bg = QColor(colors.get(typ, "#eaf4ff" if direction == "TX" else "#edf9ee"))
                if match == "unmatched":
                    bg = QColor("#fde8e8")
            for col in range(self.model.columnCount()):
                item = self.model.item(row, col)
                if item:
                    item.setBackground(bg)
                    item.setForeground(fg)

    def jump_pair(self, index) -> None:
        item = self.model.item(index.row(), 9)
        if not item:
            return
        pair = int(item.data(PAIR_ROLE) or -1)
        if 0 <= pair < self.model.rowCount():
            self.table.selectRow(pair)
            self.table.scrollTo(self.model.index(pair, 0))

    def show_details(self) -> None:
        index = self.table.currentIndex()
        if not index.isValid():
            self.details.setPlainText("No packet selected.")
            self.decode.clear()
            return
        row = index.row()
        values = [str(self.model.index(row, c).data() or "") for c in range(10)]
        ts, direction, typ, req, cpl, tag, length, addr, payload, match = values
        pair = int(self.model.item(row, 9).data(PAIR_ROLE) or -1)
        rid = trace.parse_pci_id(req)
        cid = trace.parse_pci_id(cpl)
        try:
            addr_val = int(addr, 0) if addr else 0
        except ValueError:
            addr_val = 0
        pair_line = ""
        if pair >= 0:
            pair_line = f"Paired packet: #{pair + 1} (double-click Match to jump)\n\n"
        elif match == "unmatched":
            pair_line = "Paired packet: none (unmatched request)\n\n"
        elif match == "complete":
            pair_line = "Match: complete — QEMU logged the config read and its returned DWORD on one line.\n\n"
        self.details.setPlainText(
            f"Packet #{row + 1}\nTimestamp: {ts}\nDirection: {direction}\nType: {typ}\n{pair_line}"
            f"Header fields:\n  - requester_id: {req} (0x{rid:04X})\n  - completer_id: {cpl} (0x{cid:04X})\n"
            f"  - tag: {tag}\n  - length: {length}\n  - address: {addr}\n\n"
            f"Payload (hex):\n{trace.hex_dump(payload)}\nRaw payload string: {payload or '<none>'}\n"
        )
        self.decode.clear()
        root = QTreeWidgetItem(self.decode, ["PCIe TLP", ""])
        for name, value in (
            ("Direction", direction),
            ("Type", typ),
            ("Requester ID", f"{req} (0x{rid:04X})"),
            ("Completer ID", f"{cpl} (0x{cid:04X})"),
            ("Match", f"packet #{pair + 1}" if pair >= 0 else match),
            ("Tag", tag),
            ("Length", length),
            ("Address", hex(addr_val)),
            ("Payload", payload or "<none>"),
        ):
            QTreeWidgetItem(root, [name, value])
        decode_payload = payload
        if not decode_payload.strip() and pair >= 0:
            decode_payload = str(self.model.index(pair, 8).data() or "")
        hexed = "".join(decode_payload.split())
        if typ in {"CfgRd", "CfgWr", "Cpl", "CplD", "Completion"} and len(hexed) >= 8:
            try:
                raw = bytes.fromhex(hexed[:8])
                reg = int.from_bytes(raw[:4], "little")
            except ValueError:
                raw = b""
                reg = 0
            if raw:
                pci_root = QTreeWidgetItem(self.decode, ["PCI config decode", ""])
                if addr_val == 0x00:
                    QTreeWidgetItem(pci_root, ["Vendor ID", f"0x{reg & 0xFFFF:04X}"])
                    QTreeWidgetItem(pci_root, ["Vendor name", trace.vendor_name(reg & 0xFFFF)])
                    QTreeWidgetItem(pci_root, ["Device ID", f"0x{(reg >> 16) & 0xFFFF:04X}"])
                elif addr_val == 0x08:
                    QTreeWidgetItem(pci_root, ["Revision ID", f"0x{reg & 0xFF:02X}"])
                    QTreeWidgetItem(pci_root, ["Class code", f"0x{(reg >> 8) & 0xFFFFFF:06X}"])
                    QTreeWidgetItem(pci_root, ["Class name", trace.class_name((reg >> 8) & 0xFFFFFF)])
                elif addr_val in {0x10, 0x14, 0x18, 0x1C}:
                    QTreeWidgetItem(pci_root, ["BAR", f"0x{reg:08X}"])
                else:
                    QTreeWidgetItem(pci_root, ["Raw register", f"0x{reg:08X}"])
        self.decode.expandAll()

    def enumerate_pci(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Enumerate PCI")
        form = QFormLayout(dlg)
        backend = QComboBox()
        backend.addItems(["pci", "dummy"])
        backend.setCurrentText(self.backend_name)
        device = QLineEdit(self.device_bdf)
        form.addRow("Backend", backend)
        form.addRow("Device", device)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Enumerate")
        form.addRow(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self.backend_name = backend.currentText()
        self.device_bdf = device.text().strip() or "0000:00:03.0"
        try:
            summary = pci.device_summary(self.backend_name, self.device_bdf)
            rows = []
            now = str(int(time.time() * 1000))
            for off in pci.ENUM_ADDRS:
                data = pci.read_config_dword(self.backend_name, self.device_bdf, off)
                rows.append({
                    "ts": now, "direction": "TX", "type": "CfgRd", "requester": "1", "completer": "0",
                    "tag": "15", "length": "4", "addr": hex(off), "payload": pci.hex_payload(data),
                    "match": "complete", "pair": -1,
                })
        except (OSError, RuntimeError) as exc:
            QMessageBox.warning(self, "PCI enumeration failed", str(exc))
            return
        self._set_rows(rows)
        self.status.setText(f"Enumerated PCI device ({summary})")

    def inject_fabric(self) -> None:
        rows = []
        now = str(int(time.time() * 1000))
        for bdf, role in topology.topology_nodes(self.topology):
            for i, off in enumerate(pci.ENUM_ADDRS):
                payload = topology.le_dword_payload(topology.synthetic_dword(role, off))
                rows.append({
                    "ts": now, "direction": "TX", "type": "CfgRd", "requester": "00:00.0",
                    "completer": bdf or "00:00.0", "tag": str(i), "length": "4", "addr": hex(off),
                    "payload": "", "match": "—", "pair": -1,
                })
                rows.append({
                    "ts": now, "direction": "RX", "type": "Cpl", "requester": bdf or "00:00.0",
                    "completer": "00:00.0", "tag": str(i), "length": "4", "addr": hex(off),
                    "payload": payload, "match": "—", "pair": -1,
                })
        trace.analyze(rows)
        self._set_rows(rows)

    def measure(self) -> None:
        nodes = topology.topology_nodes(self.topology)
        if not nodes:
            QMessageBox.warning(self, "Measure failed", "The current topology has no devices to walk.")
            return
        start = time.perf_counter_ns()
        txns = 0
        rounds = 0
        while True:
            for _bdf, role in nodes:
                for off in pci.ENUM_ADDRS:
                    topology.synthetic_dword(role, off)
                    txns += 1
            rounds += 1
            if time.perf_counter_ns() - start >= 50_000_000 or rounds >= 64:
                break
        elapsed = max(1, time.perf_counter_ns() - start)
        self.last_perf = {
            "devices": len(nodes),
            "txns": txns,
            "ns": elapsed,
            "rate": txns * 1e9 / elapsed,
        }
        self.inject_fabric()
        self._update_perf()
        self.status.setText(f"Measured {len(nodes)} devices on {self.topology.get('topology_name')}  ·  {self.last_perf['rate']:.0f} cfg/s")

    def _update_perf(self) -> None:
        if not self.perf_label:
            return
        if self.last_perf["txns"] <= 0:
            devices = reads = elapsed = rate = "—"
        else:
            devices = str(self.last_perf["devices"])
            reads = str(self.last_perf["txns"])
            elapsed = f"{self.last_perf['ns'] / 1e6:.2f} ms"
            rate = f"{self.last_perf['rate']:.0f} cfg/s"
        cell = "<td style='width:25%;padding:4px 10px;'><div style='font-size:11px;opacity:0.7;'>{}</div><div style='font-size:18px;font-weight:700;'>{}</div></td>"
        self.perf_label.setText(
            "<table width='100%'><tr>"
            + cell.format("Devices", devices) + cell.format("Config reads", reads)
            + cell.format("Elapsed", elapsed) + cell.format("Rate", rate)
            + "</tr></table><div style='font-size:11px;opacity:0.7;padding:2px 10px 0;'>"
            "Timed config-space walk of the deployed fabric. Not AI tokens/sec.</div>"
        )

    def _mode_title(self) -> str:
        return {"zephyr": "Zephyr golden runner", "linux": "Linux QEMU runner", "generated": "Generated topology"}.get(self.run_mode, "Topology")

    def _script(self) -> Path | None:
        root = _repo_root()
        name = "run_linux_ai_topology.sh" if self.run_mode == "linux" else "run_zephyr_ai_topology.sh"
        path = root / "scripts" / name
        return path if path.exists() else None

    def _update_source_ui(self) -> None:
        name = self.topology.get("topology_name", "unnamed")
        badge = {"zephyr": "Zephyr golden fabric", "linux": "Linux QEMU golden fabric"}.get(self.run_mode, "Generated topology")
        if self.topo_badge:
            self.topo_badge.setText(f"{badge}  ·  {name}")
        if self.run_button:
            self.run_button.setText({"zephyr": "Run Zephyr golden", "linux": "Run Linux QEMU"}.get(self.run_mode, "Run generated topology"))
        if self.fabric_box:
            self.fabric_box.setVisible(self.run_mode == "generated")
        if self.topo_view:
            self.topo_view.set_topology(self.topology)

    def open_emulator(self) -> None:
        if self.emu is None:
            self.emu = QDialog(self)
            self.emu.setWindowTitle("AI PCIe Emulator")
            self.emu.setModal(False)
            self.emu.setSizeGripEnabled(True)
            self.emu.setWindowFlag(Qt.WindowType.WindowMinMaxButtonsHint, True)
            layout = QVBoxLayout(self.emu)
            layout.setContentsMargins(12, 12, 12, 12)
            source = QGroupBox("Topology source")
            grid = QGridLayout(source)
            self.mode_combo = QComboBox()
            self.mode_combo.addItem("Zephyr golden runner", "zephyr")
            self.mode_combo.addItem("Linux QEMU runner", "linux")
            self.mode_combo.addItem("Generated from fields", "generated")
            generate = QPushButton("Generate from fields")
            self.topo_badge = QLabel()
            self.topo_badge.setObjectName("topologySourceBadge")
            grid.addWidget(QLabel("Run mode"), 0, 0)
            grid.addWidget(self.mode_combo, 0, 1)
            grid.addWidget(generate, 0, 2)
            grid.addWidget(self.topo_badge, 1, 0, 1, 3)
            self.topo_view = FabricDiagram()
            self.topo_view.setMinimumHeight(220)
            self.perf_label = QLabel()
            self.perf_label.setObjectName("summaryCard")
            self.perf_label.setWordWrap(True)
            self.perf_label.setTextFormat(Qt.TextFormat.RichText)
            self.fabric_box = QGroupBox("Fabric size")
            form = QGridLayout(self.fabric_box)
            preset = QComboBox()
            preset.addItems(["Golden fabric", "Wider mesh", "Dense fabric", "Custom"])
            roots = QSpinBox()
            roots.setRange(1, 16)
            roots.setValue(4)
            eps = QSpinBox()
            eps.setRange(1, 16)
            eps.setValue(2)
            form.addWidget(QLabel("Preset"), 0, 0)
            form.addWidget(preset, 0, 1)
            form.addWidget(QLabel("Root ports"), 0, 2)
            form.addWidget(roots, 0, 3)
            form.addWidget(QLabel("Endpoints / root"), 1, 0)
            form.addWidget(eps, 1, 1)
            self.run_button = QPushButton("Run Zephyr golden")
            measure = QPushButton("Measure performance")
            pci_list = QPushButton("Show guest PCI list")
            close = QPushButton("Close")
            actions = QDialogButtonBox()
            for btn in (self.run_button, measure, pci_list, close):
                actions.addButton(btn, QDialogButtonBox.ButtonRole.ActionRole)
            layout.addWidget(source)
            layout.addWidget(self.topo_view, 1)
            layout.addWidget(self.fabric_box)
            layout.addWidget(self.perf_label)
            layout.addWidget(actions)

            def apply_preset(index: int) -> None:
                if index == 0:
                    roots.setValue(4)
                    eps.setValue(2)
                elif index == 1:
                    roots.setValue(8)
                    eps.setValue(2)
                elif index == 2:
                    roots.setValue(8)
                    eps.setValue(4)

            def apply_mode(index: int) -> None:
                self.run_mode = self.mode_combo.itemData(index)
                if self.run_mode in {"zephyr", "linux"}:
                    self.topology = topology.golden_topology()
                else:
                    self.topology = topology.generate_topology(roots.value(), eps.value())
                pci_list.setText("Show lspci" if self.run_mode == "linux" else "Show pcie ls")
                self._update_source_ui()

            def generate_clicked() -> None:
                self.run_mode = "generated"
                self.mode_combo.setCurrentIndex(self.mode_combo.findData("generated"))
                self.topology = topology.generate_topology(roots.value(), eps.value())
                self._update_source_ui()

            self.mode_combo.currentIndexChanged.connect(apply_mode)
            generate.clicked.connect(generate_clicked)
            preset.currentIndexChanged.connect(apply_preset)
            self.run_button.clicked.connect(self._run_topology)
            measure.clicked.connect(self.measure)
            pci_list.clicked.connect(lambda: self._show_pci_list())
            close.clicked.connect(self.emu.close)
            self.emu.finished.connect(self._emu_closed)
            apply_mode(0)
            self._update_perf()
        if not self.emu.isVisible():
            self._fit(self.emu, 0.85)
        self.emu.setMinimumSize(720, 520)
        self.emu.show()
        self.emu.raise_()
        self.emu.activateWindow()

    def _emu_closed(self) -> None:
        self.emu = None
        self.topo_view = None
        self.topo_badge = None
        self.mode_combo = None
        self.run_button = None
        self.perf_label = None
        self.fabric_box = None

    def _show_pci_list(self, text: str | None = None) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(("lspci" if self.run_mode == "linux" else "pcie ls") + f"  ·  {self._mode_title()}")
        self._fit(dlg, 0.75)
        browser = QTextBrowser(dlg)
        browser.setFont(QFont("monospace"))
        browser.setPlainText(text or topology.format_pci_list(self.topology))
        QVBoxLayout(dlg).addWidget(browser)
        dlg.show()

    def _run_topology(self) -> None:
        self.inject_fabric()
        script = self._script()
        if script is None or self.run_mode == "generated":
            self.status.setText(f"{self._mode_title()} enumerated in-process")
            return
        root = _repo_root()
        log_name = "linux_ai_topology_trace.log" if self.run_mode == "linux" else "zephyr_ai_topology_trace.log"
        self.live_path = str(root / log_name)
        self.live_seen.clear()
        if self.live_timer:
            self.live_timer.stop()
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self._poll_live)
        self.live_timer.start(500)
        if self.live_proc:
            self.suppress_exit = True
            self.live_proc.kill()
        self.live_proc = QProcess(self)
        self.live_proc.setWorkingDirectory(str(root))
        self.live_proc.setProgram("bash")
        self.live_proc.setArguments([str(script)])
        env = QProcessEnvironment.systemEnvironment()
        env.insert("TRACE_LOG", self.live_path)
        env.insert("PCIE_HEADLESS", "1")
        env.insert("TOPOLOGY_MODE", "linux-golden" if self.run_mode == "linux" else "zephyr-golden")
        self.live_proc.setProcessEnvironment(env)
        self.live_proc.finished.connect(self._runner_finished)
        self.live_proc.start()
        self.status.setText(f"{self._mode_title()} started  ·  {self.topology.get('topology_name')}")

    def _poll_live(self) -> None:
        path = Path(self.live_path)
        if not path.exists():
            return
        added = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line in self.live_seen:
                continue
            parsed = trace.parse_cfg_line(line)
            if not parsed:
                continue
            self.live_seen.add(line)
            self.rows.append(parsed)
            self.model.appendRow(_items(parsed))
            added += 1
        if added:
            trace.analyze(self.rows)
            for i, row in enumerate(self.rows):
                item = self.model.item(i, 9)
                if item:
                    item.setText(str(row["match"]))
                    item.setData(int(row["pair"]), PAIR_ROLE)
            self.apply_filter()
            self.status.setText(f"{self._mode_title()} live trace: {len(self.rows)} entries")

    def _runner_finished(self, code: int, status: QProcess.ExitStatus) -> None:
        if self.suppress_exit:
            self.suppress_exit = False
            return
        if self.live_timer:
            self.live_timer.stop()
        if status == QProcess.ExitStatus.CrashExit or code != 0:
            out = self.live_proc.readAllStandardOutput().data().decode("utf-8", errors="replace") if self.live_proc else ""
            QMessageBox.warning(self, "Topology run failed", f"{self._mode_title()} exited with code {code}.\n\n{out[-1200:] or 'No runner output was captured.'}")
            return
        if Path(self.live_path).exists():
            self.load_trace(self.live_path)
            self.status.setText(f"{self._mode_title()} finished  ·  {len(self.rows)} entries")

    def closeEvent(self, event) -> None:
        if self.live_proc and self.live_proc.state() != QProcess.ProcessState.NotRunning:
            self.suppress_exit = True
            self.live_proc.terminate()
        pid_file = Path.cwd() / "qemu.pid"
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text().strip()), 15)
            except (OSError, ValueError):
                pass
        super().closeEvent(event)
