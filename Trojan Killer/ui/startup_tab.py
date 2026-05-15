from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

from core.startup_checker import StartupChecker


class StartupWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, checker, db):
        super().__init__()
        self.checker = checker
        self.db = db

    def run(self):
        try:
            items = self.checker.check_all()
            if self.db:
                self.db.delete("threat_found", "threat_type='可疑启动项'")
                threats = []
                for item in items:
                    if item.is_suspicious:
                        threats.append({
                            "scan_id": 0,
                            "threat_type": "可疑启动项",
                            "threat_name": item.name,
                            "threat_path": item.command,
                            "risk_level": "中危",
                            "process_name": item.name,
                            "process_pid": 0,
                            "description": "; ".join(item.suspicious_reasons) if item.suspicious_reasons else "可疑启动项",
                            "suggestion": "建议检查并禁用该启动项",
                        })
                if threats:
                    try:
                        self.db.insert_batch("threat_found", threats)
                    except Exception:
                        pass
            self.data_ready.emit(items)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class StartupTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.checker = StartupChecker()

        self.all_items = []
        self._activated = False
        self.worker = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.scan_btn = QPushButton("扫描启动项")
        self.scan_btn.setObjectName("dangerBtn")
        self.scan_btn.clicked.connect(self.scan_startup)
        toolbar.addWidget(self.scan_btn)

        self.show_suspicious_btn = QPushButton("仅显示可疑")
        self.show_suspicious_btn.setObjectName("warningBtn")
        self.show_suspicious_btn.setCheckable(True)
        self.show_suspicious_btn.clicked.connect(self.toggle_suspicious_filter)
        toolbar.addWidget(self.show_suspicious_btn)

        toolbar.addStretch()

        self.count_label = QLabel("共 0 项")
        toolbar.addWidget(self.count_label)

        layout.addLayout(toolbar)

        self.startup_table = QTableWidget()
        self.startup_table.setColumnCount(5)
        self.startup_table.setHorizontalHeaderLabels([
            "类型", "名称", "位置", "命令/路径", "可疑"
        ])
        self.startup_table.horizontalHeader().setStretchLastSection(True)
        self.startup_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.startup_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.startup_table.setAlternatingRowColors(True)
        self.startup_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.startup_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        layout.addWidget(self.startup_table)

    def scan_startup(self):
        if self.worker and self.worker.isRunning():
            return
        self.count_label.setText("正在扫描...")
        self.scan_btn.setEnabled(False)
        self.worker = StartupWorker(self.checker, self.main_window.db)
        self.worker.data_ready.connect(self._on_scan_done)
        self.worker.start()

    def _on_scan_done(self, data):
        self.scan_btn.setEnabled(True)
        if isinstance(data, dict) and "error" in data:
            self.count_label.setText("扫描失败")
            print(f"启动项扫描失败: {data['error']}")
            return
        self.all_items = data
        self.display_items(data)
        suspicious_count = sum(1 for i in data if i.is_suspicious)
        self.count_label.setText(f"共 {len(data)} 项 (可疑 {suspicious_count} 项)")

    def display_items(self, items):
        sorted_items = sorted(items, key=lambda x: (0 if x.is_suspicious else 1, x.name.lower()))
        self.startup_table.setRowCount(len(sorted_items))
        for i, item in enumerate(sorted_items):
            self.startup_table.setItem(i, 0, QTableWidgetItem(item.item_type))
            self.startup_table.setItem(i, 1, QTableWidgetItem(item.name))
            self.startup_table.setItem(i, 2, QTableWidgetItem(item.location))
            self.startup_table.setItem(i, 3, QTableWidgetItem(item.command))

            suspicious_item = QTableWidgetItem("是" if item.is_suspicious else "否")
            if item.is_suspicious:
                suspicious_item.setForeground(QBrush(QColor("#e94560")))
                suspicious_item.setToolTip("\n".join(item.suspicious_reasons) if item.suspicious_reasons else "")
                for col in range(5):
                    current = self.startup_table.item(i, col)
                    if current:
                        current.setBackground(QColor(0x3a, 0x15, 0x20))
            else:
                suspicious_item.setForeground(QBrush(QColor("#27ae60")))
            self.startup_table.setItem(i, 4, suspicious_item)

    def toggle_suspicious_filter(self):
        if self.show_suspicious_btn.isChecked():
            suspicious = [i for i in self.all_items if i.is_suspicious]
            self.display_items(suspicious)
            self.show_suspicious_btn.setText("显示全部")
            self.count_label.setText(f"可疑 {len(suspicious)} 项")
        else:
            self.display_items(self.all_items)
            self.show_suspicious_btn.setText("仅显示可疑")
            self.count_label.setText(f"共 {len(self.all_items)} 项")

    def on_activate(self):
        if not self._activated:
            self._activated = True
            self.scan_startup()
