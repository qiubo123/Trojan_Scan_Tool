from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QMessageBox, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

from core.software_scanner import SoftwareScanner


class SoftwareWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner

    def run(self):
        try:
            programs = self.scanner.scan()
            self.data_ready.emit(programs)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class SoftwareTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.scanner = SoftwareScanner()
        self.all_programs = []
        self._activated = False
        self.worker = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.scan_btn = QPushButton("刷新程序列表")
        self.scan_btn.setObjectName("dangerBtn")
        self.scan_btn.clicked.connect(self.scan_programs)
        toolbar.addWidget(self.scan_btn)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索程序名称...")
        self.search_input.setMinimumWidth(200)
        self.search_input.textChanged.connect(self.filter_programs)
        toolbar.addWidget(self.search_input)

        toolbar.addStretch()

        self.count_label = QLabel("共 0 个程序")
        toolbar.addWidget(self.count_label)

        layout.addLayout(toolbar)

        self.software_table = QTableWidget()
        self.software_table.setColumnCount(8)
        self.software_table.setHorizontalHeaderLabels([
            "程序名称", "版本", "发布者", "安装日期", "安装路径", "大小(MB)", "风险标记", "卸载命令"
        ])
        self.software_table.horizontalHeader().setStretchLastSection(True)
        self.software_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.software_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.software_table.setAlternatingRowColors(True)
        self.software_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.software_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.software_table.setSortingEnabled(True)
        layout.addWidget(self.software_table)

    def scan_programs(self, force=False):
        if self.worker and self.worker.isRunning():
            return
        
        if not force and self.all_programs:
            return
            
        self.count_label.setText("正在扫描已安装程序...")
        self.scan_btn.setEnabled(False)
        self.worker = SoftwareWorker(self.scanner)
        self.worker.data_ready.connect(self._on_scan_done)
        self.worker.start()

    def _on_scan_done(self, data):
        self.scan_btn.setEnabled(True)
        if isinstance(data, dict) and "error" in data:
            self.count_label.setText("扫描失败")
            print(f"程序扫描失败: {data['error']}")
            return
        self.all_programs = data
        keyword = self.search_input.text().strip().lower()
        if keyword:
            self.filter_programs()
        else:
            self.display_programs(data)
            self.count_label.setText(f"共 {len(data)} 个程序")

    def _is_vpn_program(self, name):
        if self.scanner.is_vpn_program(name):
            return "VPN程序"
        name_lower = name.lower()
        if "proxy" in name_lower or "unblock" in name_lower or "bypass" in name_lower:
            return "可疑代理"
        return ""

    def display_programs(self, programs):
        sorted_programs = sorted(programs, key=lambda x: (0 if self._is_vpn_program(x["name"]) else 1, x["name"].lower()))
        
        self.software_table.setSortingEnabled(False)
        self.software_table.setRowCount(len(sorted_programs))
        for i, prog in enumerate(sorted_programs):
            self.software_table.setItem(i, 0, QTableWidgetItem(prog["name"]))
            self.software_table.setItem(i, 1, QTableWidgetItem(prog["version"]))
            self.software_table.setItem(i, 2, QTableWidgetItem(prog["publisher"]))
            self.software_table.setItem(i, 3, QTableWidgetItem(prog["install_date"]))
            self.software_table.setItem(i, 4, QTableWidgetItem(prog["install_location"]))
            size_text = str(prog["size_mb"]) if prog["size_mb"] else ""
            self.software_table.setItem(i, 5, QTableWidgetItem(size_text))
            
            risk_tag = self._is_vpn_program(prog["name"])
            risk_item = QTableWidgetItem(risk_tag)
            if risk_tag:
                risk_item.setForeground(QColor("#e94560"))
                risk_item.setBackground(QBrush(QColor("#ffebee")))
            self.software_table.setItem(i, 6, risk_item)
            
            self.software_table.setItem(i, 7, QTableWidgetItem(prog["uninstall_string"]))
        self.software_table.setSortingEnabled(True)

    def filter_programs(self):
        keyword = self.search_input.text().strip().lower()
        if not keyword:
            self.display_programs(self.all_programs)
            self.count_label.setText(f"共 {len(self.all_programs)} 个程序")
            return
        filtered = [p for p in self.all_programs if keyword in p["name"].lower()]
        self.display_programs(filtered)
        self.count_label.setText(f"找到 {len(filtered)} 个程序")

    def on_activate(self):
        if not self._activated:
            self._activated = True
            cached_programs = self.scanner.programs
            if cached_programs:
                self.all_programs = cached_programs
                self.display_programs(cached_programs)
                self.count_label.setText(f"共 {len(cached_programs)} 个程序")
            else:
                self.scan_programs()
