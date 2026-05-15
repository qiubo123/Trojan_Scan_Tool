from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QFrame, QProgressBar, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from core.process_monitor import ProcessMonitor
from core.network_detector import NetworkDetector
from core.user_checker import UserChecker
from core.browser_checker import detect_vpn_extensions, check_proxy_settings
from core.software_scanner import SoftwareScanner


class SystemInfoWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def run(self):
        try:
            # 使用轻量模式获取进程信息
            processes = self.monitor.get_all_processes_light()
            sys_info = self.monitor.get_system_info()
            # 添加可疑进程数量
            sys_info['suspicious_count'] = sum(1 for p in processes if p.is_suspicious)
            self.data_ready.emit(sys_info)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ConnectionStatsWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, detector):
        super().__init__()
        self.detector = detector

    def run(self):
        try:
            conn_stats = self.detector.get_connection_statistics()
            self.data_ready.emit(conn_stats)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class UserStatsWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, checker):
        super().__init__()
        self.checker = checker

    def run(self):
        try:
            user_stats = self.checker.get_user_statistics()
            self.data_ready.emit(user_stats)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ThreatWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            import time
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            from core.browser_checker import detect_vpn_extensions, check_proxy_settings
            from core.software_scanner import SoftwareScanner
            from core.startup_checker import StartupChecker
            
            vpn_extensions = detect_vpn_extensions()
            proxy_settings = check_proxy_settings()
            
            scanner = SoftwareScanner()
            software = scanner.scan()
            vpn_programs = [s for s in software if scanner.is_vpn_program(s.get("name", ""))]
            
            startup_checker = StartupChecker()
            startup_items = startup_checker.check_all()
            suspicious_startups = [item for item in startup_items if getattr(item, "is_suspicious", False)]
            
            threats = []
            
            for ext in vpn_extensions:
                exists = self.db.fetch_one(
                    "SELECT id FROM threat_found WHERE threat_type=? AND threat_name=?",
                    ("VPN/代理软件", ext.get("name", ""))
                )
                if not exists:
                    self.db.insert("threat_found", {
                        "threat_type": "VPN/代理软件",
                        "threat_name": ext.get("name", ""),
                        "threat_path": ext.get("path", ""),
                        "risk_level": "高危",
                        "process_name": "-",
                        "status": "未处理",
                        "description": f"浏览器插件: {ext.get('browser', '')} | {ext.get('reason', '')}",
                        "found_time": current_time
                    })
            
            for prog in vpn_programs:
                exists = self.db.fetch_one(
                    "SELECT id FROM threat_found WHERE threat_type=? AND threat_name=?",
                    ("VPN/代理软件", prog.get("name", ""))
                )
                if not exists:
                    self.db.insert("threat_found", {
                        "threat_type": "VPN/代理软件",
                        "threat_name": prog.get("name", ""),
                        "risk_level": "高危",
                        "process_name": "-",
                        "status": "未处理",
                        "description": "已安装的VPN/代理软件",
                        "found_time": current_time
                    })
            
            for setting in proxy_settings:
                threat_name = setting.get("type", "系统代理设置")
                exists = self.db.fetch_one(
                    "SELECT id FROM threat_found WHERE threat_type=? AND threat_name=?",
                    ("VPN/代理软件", threat_name)
                )
                if not exists:
                    self.db.insert("threat_found", {
                        "threat_type": "VPN/代理软件",
                        "threat_name": threat_name,
                        "risk_level": "中危",
                        "process_name": "-",
                        "status": "未处理",
                        "description": f"{setting.get('status', '')} | {setting.get('details', '')}",
                        "found_time": current_time
                    })
            
            for item in suspicious_startups:
                exists = self.db.fetch_one(
                    "SELECT id FROM threat_found WHERE threat_type=? AND threat_name=?",
                    ("可疑启动项", getattr(item, "name", ""))
                )
                if not exists:
                    self.db.insert("threat_found", {
                        "threat_type": "可疑启动项",
                        "threat_name": getattr(item, "name", ""),
                        "threat_path": getattr(item, "path", ""),
                        "risk_level": "中危",
                        "process_name": "-",
                        "status": "未处理",
                        "description": "; ".join(getattr(item, "suspicious_reasons", [])),
                        "found_time": current_time
                    })
            
            all_threats = self.db.fetch_all(
                "SELECT * FROM threat_found ORDER BY found_time DESC LIMIT 50"
            )
            self.data_ready.emit(all_threats)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class VpnCheckerWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            vpn_extensions = detect_vpn_extensions()
            proxy_settings = check_proxy_settings()
            
            scanner = SoftwareScanner()
            software = scanner.scan()
            vpn_programs = [s for s in software if scanner.is_vpn_program(s.get("name", ""))]
            
            vpn_extensions_data = [{
                "name": ext.get("name", ""),
                "browser": ext.get("browser", ""),
                "path": ext.get("path", ""),
                "reason": ext.get("reason", "")
            } for ext in vpn_extensions]
            
            proxy_settings_data = [{
                "type": setting.get("type", "系统代理设置"),
                "status": setting.get("status", ""),
                "details": setting.get("details", "")
            } for setting in proxy_settings]
            
            vpn_programs_data = [{
                "name": prog.get("name", ""),
                "version": prog.get("version", ""),
                "publisher": prog.get("publisher", ""),
                "install_date": prog.get("install_date", "")
            } for prog in vpn_programs]
            
            self.data_ready.emit({
                "vpn_extensions": vpn_extensions_data,
                "proxy_settings": proxy_settings_data,
                "vpn_programs": vpn_programs_data
            })
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class StatCard(QFrame):
    def __init__(self, title, value, unit="", color="#4fc3f7", icon=""):
        super().__init__()
        self.setObjectName("statCard")
        self.setMinimumHeight(110)
        self.setMaximumHeight(130)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(16, 12, 16, 12)

        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

        if icon:
            icon_label = QLabel(icon)
            icon_label.setStyleSheet(f"font-size: 18px; color: {color};")
            header_layout.addWidget(icon_label)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #a0a0a0; font-size: 12px;")
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        value_layout = QHBoxLayout()
        value_layout.setSpacing(4)

        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(f"color: {color}; font-size: 30px; font-weight: bold;")
        value_layout.addWidget(self.value_label)

        if unit:
            self.unit_label = QLabel(unit)
            self.unit_label.setStyleSheet("color: #a0a0a0; font-size: 14px;")
            self.unit_label.setAlignment(Qt.AlignmentFlag.AlignBottom)
            value_layout.addWidget(self.unit_label)

        value_layout.addStretch()
        layout.addLayout(value_layout)

    def update_value(self, value, unit=""):
        self.value_label.setText(str(value))
        if unit:
            self.unit_label.setText(unit)


class ProgressCard(QFrame):
    def __init__(self, title, value=0, unit="%", color="#4fc3f7"):
        super().__init__()
        self.setObjectName("statCard")
        self.setMinimumHeight(90)
        self.setMaximumHeight(110)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(16, 12, 16, 12)

        header_layout = QHBoxLayout()
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #a0a0a0; font-size: 12px;")
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()

        self.value_label = QLabel(f"{value}{unit}")
        self.value_label.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold;")
        header_layout.addWidget(self.value_label)
        layout.addLayout(header_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(value)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #0d1b3e;
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(self.progress_bar)

    def update_value(self, value, unit="%"):
        self.value_label.setText(f"{value}{unit}")
        self.progress_bar.setValue(min(int(value), 100))


class DashboardTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.monitor = ProcessMonitor()
        self.detector = NetworkDetector()
        self.user_checker = UserChecker()

        self._activated = False
        self._pending_refresh = False
        self._workers = []

        self.init_ui()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.setInterval(15000)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        title_label = QLabel("系统安全仪表盘")
        title_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title_label)

        subtitle_label = QLabel("实时监控系统运行状态，及时发现安全威胁")
        subtitle_label.setStyleSheet("color: #a0a0a0; font-size: 12px; margin-bottom: 4px;")
        layout.addWidget(subtitle_label)

        grid = QGridLayout()
        grid.setSpacing(10)

        self.cpu_card = ProgressCard("CPU使用率", 0, "%", "#4fc3f7")
        grid.addWidget(self.cpu_card, 0, 0)

        self.mem_card = ProgressCard("内存使用率", 0, "%", "#81c784")
        grid.addWidget(self.mem_card, 0, 1)

        self.disk_card = ProgressCard("磁盘使用率", 0, "%", "#ffb74d")
        grid.addWidget(self.disk_card, 0, 2)

        self.process_card = StatCard("运行进程数", "0", "个", "#e94560", "⚙")
        grid.addWidget(self.process_card, 0, 3)

        self.conn_card = StatCard("网络连接数", "0", "个", "#ba68c8", "🌐")
        grid.addWidget(self.conn_card, 1, 0)

        self.malicious_card = StatCard("恶意连接", "0", "个", "#e94560", "⚠")
        grid.addWidget(self.malicious_card, 1, 1)

        self.user_card = StatCard("用户账户", "0", "个", "#4db6ac", "👤")
        grid.addWidget(self.user_card, 1, 2)

        self.threat_card = StatCard("累计威胁", "0", "个", "#e94560", "🛡")
        grid.addWidget(self.threat_card, 1, 3)

        self.vpn_card = StatCard("VPN/代理检测", "0", "个", "#ff9800", "🔒")
        grid.addWidget(self.vpn_card, 2, 0)

        layout.addLayout(grid)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        sys_group = QGroupBox("系统信息")
        sys_group.setMinimumWidth(280)
        sys_layout = QVBoxLayout(sys_group)
        sys_layout.setSpacing(8)

        self.sys_info_widget = QWidget()
        sys_info_layout = QVBoxLayout(self.sys_info_widget)
        sys_info_layout.setSpacing(6)
        sys_info_layout.setContentsMargins(0, 0, 0, 0)

        self.sys_items = {}
        sys_labels = [
            ("os_version", "系统版本", "🖥"),
            ("hostname", "主机名", "🏠"),
            ("boot_time", "系统启动时间", "⏱"),
            ("cpu_count", "CPU核心数", "💻"),
            ("ip_address", "IP地址", "🌐"),
            ("mac_address", "MAC地址", "🔗"),
        ]
        for key, label, icon in sys_labels:
            item_layout = QHBoxLayout()
            item_layout.setSpacing(8)
            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 14px;")
            item_layout.addWidget(icon_lbl)
            name_lbl = QLabel(label)
            name_lbl.setStyleSheet("color: #a0a0a0; font-size: 12px;")
            name_lbl.setFixedWidth(90)
            item_layout.addWidget(name_lbl)
            value_lbl = QLabel("获取中...")
            value_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px;")
            value_lbl.setObjectName(f"sys_{key}")
            value_lbl.setWordWrap(True)
            item_layout.addWidget(value_lbl, stretch=1)
            sys_info_layout.addLayout(item_layout)
            self.sys_items[key] = value_lbl

        sys_layout.addWidget(self.sys_info_widget)
        sys_layout.addStretch()
        splitter.addWidget(sys_group)

        vpn_group = QGroupBox("VPN/代理检测")
        vpn_group.setMinimumWidth(300)
        vpn_layout = QVBoxLayout(vpn_group)
        self.vpn_table = QTableWidget()
        self.vpn_table.setColumnCount(4)
        self.vpn_table.setHorizontalHeaderLabels(["类型", "浏览器", "名称", "原因"])
        self.vpn_table.horizontalHeader().setStretchLastSection(True)
        self.vpn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.vpn_table.setAlternatingRowColors(True)
        self.vpn_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vpn_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        vpn_layout.addWidget(self.vpn_table)
        
        self.vpn_detail_btn = QPushButton("查看详情")
        self.vpn_detail_btn.setEnabled(False)
        self.vpn_detail_btn.clicked.connect(self.show_vpn_detail)
        vpn_layout.addWidget(self.vpn_detail_btn)
        
        self._vpn_details = []
        splitter.addWidget(vpn_group)

        threat_group = QGroupBox("最近威胁告警")
        threat_layout = QVBoxLayout(threat_group)
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["时间", "类型", "名称", "风险等级"])
        self.threat_table.horizontalHeader().setStretchLastSection(True)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.threat_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        threat_layout.addWidget(self.threat_table)
        splitter.addWidget(threat_group)

        layout.addWidget(splitter, stretch=1)

        refresh_layout = QHBoxLayout()
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #a0a0a0; font-size: 12px;")
        refresh_layout.addWidget(self.status_label)
        refresh_layout.addStretch()
        self.refresh_btn = QPushButton("立即刷新")
        self.refresh_btn.clicked.connect(self.refresh_data)
        refresh_layout.addWidget(self.refresh_btn)
        layout.addLayout(refresh_layout)

    def refresh_data(self):
        if self._pending_refresh:
            return
        self._pending_refresh = True
        self._workers = []
        self.status_label.setText("正在刷新...")

        sys_worker = SystemInfoWorker(self.monitor)
        sys_worker.data_ready.connect(self._on_sys_info)
        self._workers.append(sys_worker)

        conn_worker = ConnectionStatsWorker(self.detector)
        conn_worker.data_ready.connect(self._on_conn_stats)
        self._workers.append(conn_worker)

        user_worker = UserStatsWorker(self.user_checker)
        user_worker.data_ready.connect(self._on_user_stats)
        self._workers.append(user_worker)

        threat_worker = ThreatWorker(self.main_window.db)
        threat_worker.data_ready.connect(self._on_threats)
        self._workers.append(threat_worker)

        vpn_worker = VpnCheckerWorker(self.main_window.db)
        vpn_worker.data_ready.connect(self._on_vpn_check)
        self._workers.append(vpn_worker)

        for w in self._workers:
            w.finished.connect(self._check_all_done)
            w.start()

    def _check_all_done(self):
        for w in self._workers:
            if w.isRunning():
                return
        self._pending_refresh = False
        self.status_label.setText("就绪")

    def _on_sys_info(self, data):
        if isinstance(data, dict) and "error" not in data:
            self.cpu_card.update_value(data.get("cpu_percent", 0))
            self.mem_card.update_value(data.get("memory_percent", 0))
            self.disk_card.update_value(data.get("disk_percent", 0))
            self.process_card.update_value(data.get("process_count", 0))

            boot_time = data.get("boot_time", "N/A")
            cpu_count = data.get("cpu_count", 0)
            os_version = data.get("os_version", "N/A")
            hostname = data.get("hostname", "N/A")
            ip_addresses = data.get("ip_addresses", [])
            mac_addresses = data.get("mac_addresses", [])

            if "os_version" in self.sys_items:
                self.sys_items["os_version"].setText(os_version)
            if "hostname" in self.sys_items:
                self.sys_items["hostname"].setText(hostname)
            if "boot_time" in self.sys_items:
                self.sys_items["boot_time"].setText(boot_time)
            if "cpu_count" in self.sys_items:
                self.sys_items["cpu_count"].setText(str(cpu_count))

            if "ip_address" in self.sys_items:
                ip_text = "\n".join(i["address"] for i in ip_addresses) if ip_addresses else "无"
                self.sys_items["ip_address"].setText(ip_text)
            if "mac_address" in self.sys_items:
                mac_text = "\n".join(m["address"] for m in mac_addresses) if mac_addresses else "无"
                self.sys_items["mac_address"].setText(mac_text)

    def _on_conn_stats(self, data):
        if isinstance(data, dict) and "error" not in data:
            self.conn_card.update_value(data.get("total", 0))
            self.malicious_card.update_value(data.get("malicious", 0))

    def _on_user_stats(self, data):
        if isinstance(data, dict) and "error" not in data:
            total = data.get("total", 0)
            suspicious = data.get("suspicious", 0)
            self.user_card.update_value(f"{total} (可疑{suspicious})")

    def _on_threats(self, data):
        if isinstance(data, list):
            self.threat_card.update_value(len(data))
            self.threat_table.setRowCount(len(data))
            for i, threat in enumerate(data):
                self.threat_table.setItem(i, 0, QTableWidgetItem(str(threat["found_time"] if threat["found_time"] else "")))
                self.threat_table.setItem(i, 1, QTableWidgetItem(str(threat["threat_type"] if threat["threat_type"] else "")))
                self.threat_table.setItem(i, 2, QTableWidgetItem(str(threat["threat_name"] if threat["threat_name"] else "")))
                risk = str(threat["risk_level"] if threat["risk_level"] else "")
                risk_item = QTableWidgetItem(risk)
                if risk == "高危":
                    risk_item.setForeground(QColor("#e94560"))
                elif risk == "中危":
                    risk_item.setForeground(QColor("#f39c12"))
                else:
                    risk_item.setForeground(QColor("#27ae60"))
                self.threat_table.setItem(i, 3, risk_item)

    def _on_vpn_check(self, data):
        if isinstance(data, dict) and "error" not in data:
            vpn_extensions = data.get("vpn_extensions", [])
            proxy_settings = data.get("proxy_settings", [])
            vpn_programs = data.get("vpn_programs", [])
            total_count = len(vpn_extensions) + len(proxy_settings) + len(vpn_programs)
            self.vpn_card.update_value(total_count)
            self._vpn_details = []
            
            self.vpn_table.setRowCount(total_count)
            self.vpn_detail_btn.setEnabled(total_count > 0)
            row = 0
            
            for ext in vpn_extensions:
                self.vpn_table.setItem(row, 0, QTableWidgetItem("浏览器插件"))
                self.vpn_table.setItem(row, 1, QTableWidgetItem(str(ext.get("browser", ""))))
                self.vpn_table.setItem(row, 2, QTableWidgetItem(str(ext.get("name", ""))))
                self.vpn_table.setItem(row, 3, QTableWidgetItem(str(ext.get("reason", ""))))
                self._vpn_details.append({
                    "type": "浏览器插件",
                    "browser": ext.get("browser", ""),
                    "name": ext.get("name", ""),
                    "version": ext.get("version", ""),
                    "id": ext.get("id", ""),
                    "path": ext.get("path", ""),
                    "reason": ext.get("reason", ""),
                })
                row += 1
            
            for program in vpn_programs:
                self.vpn_table.setItem(row, 0, QTableWidgetItem("已安装程序"))
                self.vpn_table.setItem(row, 1, QTableWidgetItem("-"))
                self.vpn_table.setItem(row, 2, QTableWidgetItem(str(program.get("name", ""))))
                self.vpn_table.setItem(row, 3, QTableWidgetItem(str(program.get("reason", ""))))
                self._vpn_details.append({
                    "type": "已安装程序",
                    "name": program.get("name", ""),
                    "version": program.get("version", ""),
                    "publisher": program.get("publisher", ""),
                    "install_date": program.get("install_date", ""),
                    "reason": program.get("reason", ""),
                })
                row += 1
            
            for setting in proxy_settings:
                self.vpn_table.setItem(row, 0, QTableWidgetItem(str(setting.get("type", ""))))
                self.vpn_table.setItem(row, 1, QTableWidgetItem("-"))
                self.vpn_table.setItem(row, 2, QTableWidgetItem(str(setting.get("status", ""))))
                self.vpn_table.setItem(row, 3, QTableWidgetItem(str(setting.get("details", ""))))
                self._vpn_details.append({
                    "type": setting.get("type", ""),
                    "status": setting.get("status", ""),
                    "details": setting.get("details", ""),
                })
                row += 1

    def show_vpn_detail(self):
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("VPN/代理检测详情")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFontFamily("Courier New")
        text_edit.setFontPointSize(10)
        
        detail_text = ""
        for i, detail in enumerate(self._vpn_details, 1):
            detail_text += f"=== 检测项 {i} ===\n"
            for key, value in detail.items():
                if value:
                    detail_text += f"{key}: {value}\n"
            detail_text += "\n"
        
        text_edit.setPlainText(detail_text)
        layout.addWidget(text_edit)
        
        btn_layout = QHBoxLayout()
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.close)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        dialog.exec()

    def on_activate(self):
        if not self._activated:
            self._activated = True
            self.refresh_timer.start()
            self.refresh_data()
