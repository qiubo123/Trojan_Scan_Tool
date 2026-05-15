from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QGroupBox, QMessageBox, QSplitter,
    QTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

from core.user_checker import UserChecker


class UserWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, checker, db):
        super().__init__()
        self.checker = checker
        self.db = db

    def run(self):
        try:
            users = self.checker.get_all_users()
            groups = self.checker.get_user_groups()
            if self.db:
                self.db.delete("threat_found", "threat_type='可疑用户'")
                threats = []
                for u in users:
                    if u.is_suspicious:
                        threats.append({
                            "scan_id": 0,
                            "threat_type": "可疑用户",
                            "threat_name": u.name,
                            "risk_level": "中危",
                            "process_name": "",
                            "process_pid": 0,
                            "description": "; ".join(u.suspicious_reasons) if u.suspicious_reasons else "可疑用户账户",
                            "suggestion": "建议检查该用户账户，必要时禁用或删除",
                        })
                if threats:
                    try:
                        self.db.insert_batch("threat_found", threats)
                    except Exception:
                        pass
            self.data_ready.emit({"users": users, "groups": groups})
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class UserTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.checker = UserChecker()

        self.all_users = []
        self._activated = False
        self.user_worker = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.refresh_btn = QPushButton("刷新用户列表")
        self.refresh_btn.clicked.connect(self.refresh_users)
        toolbar.addWidget(self.refresh_btn)

        self.show_suspicious_btn = QPushButton("仅显示可疑")
        self.show_suspicious_btn.setObjectName("warningBtn")
        self.show_suspicious_btn.setCheckable(True)
        self.show_suspicious_btn.clicked.connect(self.toggle_suspicious_filter)
        toolbar.addWidget(self.show_suspicious_btn)

        toolbar.addStretch()

        self.count_label = QLabel("共 0 个用户")
        toolbar.addWidget(self.count_label)

        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.user_table = QTableWidget()
        self.user_table.setColumnCount(5)
        self.user_table.setHorizontalHeaderLabels([
            "用户名", "全名", "SID", "状态", "可疑"
        ])
        self.user_table.horizontalHeader().setStretchLastSection(True)
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.user_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.user_table.setAlternatingRowColors(True)
        self.user_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.user_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.user_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.user_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        splitter.addWidget(self.user_table)

        self.group_group = QGroupBox("用户组信息")
        self.group_group.setVisible(False)
        group_layout = QVBoxLayout(self.group_group)
        self.group_text = QTextEdit()
        self.group_text.setReadOnly(True)
        group_layout.addWidget(self.group_text)
        splitter.addWidget(self.group_group)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def refresh_users(self, force=False):
        if self.user_worker and self.user_worker.isRunning():
            return
        
        if not force and self.all_users:
            return

        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("加载中...")
        self.count_label.setText("正在获取用户列表...")

        def on_data_ready(data):
            self.refresh_btn.setEnabled(True)
            self.refresh_btn.setText("刷新用户列表")
            if "error" in data:
                self.count_label.setText("刷新失败")
                print(f"获取用户列表失败: {data['error']}")
                return

            users = data["users"]
            groups = data["groups"]

            self.all_users = users
            self.display_users(users)

            self.group_group.setVisible(True)
            text = f"【用户组列表 ({len(groups)} 个)】\n\n"
            for g in groups:
                name = g["name"]
                sid = g.get("sid", "")
                if sid:
                    text += f"  组名: {name}\n  SID: {sid}\n\n"
                else:
                    text += f"  组名: {name}\n\n"
            self.group_text.setText(text.strip())

            suspicious = sum(1 for u in users if u.is_suspicious)
            self.count_label.setText(f"共 {len(users)} 个用户 (可疑 {suspicious} 个)")

        self.user_worker = UserWorker(self.checker, self.main_window.db)
        self.user_worker.data_ready.connect(on_data_ready)
        self.user_worker.start()

    def display_users(self, users):
        sorted_users = sorted(users, key=lambda x: (0 if x.is_suspicious else 1, x.name.lower()))
        self.user_table.setRowCount(len(sorted_users))
        for i, user in enumerate(sorted_users):
            self.user_table.setItem(i, 0, QTableWidgetItem(user.name))
            self.user_table.setItem(i, 1, QTableWidgetItem(user.full_name))
            self.user_table.setItem(i, 2, QTableWidgetItem(user.sid))

            status_text = "已禁用" if user.disabled else "正常"
            status_item = QTableWidgetItem(status_text)
            if user.disabled:
                status_item.setForeground(QBrush(QColor("#a0a0a0")))
            else:
                status_item.setForeground(QBrush(QColor("#27ae60")))
            self.user_table.setItem(i, 3, status_item)

            suspicious_item = QTableWidgetItem("是" if user.is_suspicious else "否")
            if user.is_suspicious:
                suspicious_item.setForeground(QBrush(QColor("#e94560")))
                suspicious_item.setToolTip("\n".join(user.suspicious_reasons) if user.suspicious_reasons else "")
                for col in range(5):
                    current = self.user_table.item(i, col)
                    if current:
                        current.setBackground(QColor(0x3a, 0x15, 0x20))
            else:
                suspicious_item.setForeground(QBrush(QColor("#27ae60")))
            self.user_table.setItem(i, 4, suspicious_item)

    def toggle_suspicious_filter(self):
        if self.show_suspicious_btn.isChecked():
            suspicious = [u for u in self.all_users if u.is_suspicious]
            self.display_users(suspicious)
            self.show_suspicious_btn.setText("显示全部")
            self.count_label.setText(f"可疑 {len(suspicious)} 个用户")
        else:
            self.display_users(self.all_users)
            self.show_suspicious_btn.setText("仅显示可疑")
            self.count_label.setText(f"共 {len(self.all_users)} 个用户")

    def on_activate(self):
        if not self._activated:
            self._activated = True
            self.refresh_users()
