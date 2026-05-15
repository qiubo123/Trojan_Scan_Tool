from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QStatusBar, QLabel,
    QMenuBar, QMenu, QMessageBox, QApplication
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QAction

from .styles import MAIN_STYLE
from .dashboard_tab import DashboardTab
from .process_tab import ProcessTab
from .threat_intel_tab import ThreatIntelTab

from .startup_tab import StartupTab
from .user_tab import UserTab
from .connection_tab import ConnectionTab
from .report_tab import ReportTab
from .log_tab import LogTab
from .software_tab import SoftwareTab
from core.db import DatabaseManager
from .msg_box import show_question, show_about
from core.connection_logger import ConnectionLogger


class PreloadWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            self.progress.emit("正在初始化数据库...")
            import time
            time.sleep(0.3)
            
            self.progress.emit("正在扫描VPN/代理软件...")
            self._run_with_timeout(self._scan_vpn_threats, timeout=15)
            time.sleep(0.3)
            
            self.progress.emit("正在捕获网络连接...")
            from core.connection_logger import ConnectionLogger
            logger = ConnectionLogger()
            self._run_with_timeout(lambda: logger.capture_snapshot(), timeout=10)
            time.sleep(0.3)
            
            self.progress.emit("正在检测进程...")
            from core.process_monitor import ProcessMonitor
            monitor = ProcessMonitor()
            self._run_with_timeout(lambda: monitor.get_all_processes_light(), timeout=15)
            time.sleep(0.3)
            
            self.progress.emit("正在扫描启动项...")
            from core.startup_checker import StartupChecker
            checker = StartupChecker()
            checker.check_all()
            time.sleep(0.3)
            
            self.progress.emit("正在检测用户账户...")
            from core.user_checker import UserChecker
            checker = UserChecker()
            checker.get_all_users()
            time.sleep(0.3)
            
            self.progress.emit("正在扫描已安装程序...")
            from core.software_scanner import SoftwareScanner
            scanner = SoftwareScanner()
            scanner.scan()
            time.sleep(0.3)
            
            self.progress.emit("正在收集系统日志...")
            from core.log_collector import LogCollector
            collector = LogCollector()
            from datetime import datetime, timedelta
            start_time = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            collector.collect_all(start_time, end_time)
            time.sleep(0.3)
            
            self.progress.emit("正在初始化情报数据...")
            from core.malicious_ip import MaliciousIPManager
            ip_manager = MaliciousIPManager()
            time.sleep(0.3)
            
            self.progress.emit("加载完成")
            time.sleep(0.2)
            
            self.done.emit()
        except Exception as e:
            print(f"预加载失败: {e}")
            self.done.emit()

    def _run_with_timeout(self, func, timeout=10):
        import threading
        result = []
        exception = []

        def worker():
            try:
                result.append(func())
            except Exception as e:
                exception.append(e)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=timeout)
        if t.is_alive():
            print(f"操作超时(>{timeout}s)，已跳过")
        if exception:
            raise exception[0]
        return result[0] if result else None

    def _scan_vpn_threats(self):
        import time
        from core.browser_checker import detect_vpn_extensions, check_proxy_settings
        vpn_extensions = detect_vpn_extensions()
        proxy_settings = check_proxy_settings()
        
        VPN_KEYWORDS = [
            "vpn", "clash", "v2ray", "shadowsocks", "ssr", "trojan",
            "psiphon", "lantern", "expressvpn", "nordvpn", "surfshark",
            "openvpn", "wireguard", "tor", "proxifier", "dotsvpn",
            "kuailian", "快连", "tianxing", "天行", "aurora", "极光",
            "huojian", "火箭", "laowang", "老王", "chuansuo", "穿梭"
        ]
        import winreg
        vpn_programs = []
        seen = set()
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hkey, path in reg_paths:
            try:
                key = winreg.OpenKey(hkey, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        except FileNotFoundError:
                            winreg.CloseKey(subkey)
                            continue
                        if not name or name in seen:
                            winreg.CloseKey(subkey)
                            continue
                        seen.add(name)
                        name_lower = name.lower()
                        for keyword in VPN_KEYWORDS:
                            if keyword in name_lower:
                                vpn_programs.append({"name": name})
                                break
                        winreg.CloseKey(subkey)
                    except (FileNotFoundError, OSError):
                        continue
                winreg.CloseKey(key)
            except FileNotFoundError:
                continue
        
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        
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


class AutoLogWorker(QThread):
    done = pyqtSignal(int)

    def __init__(self, logger):
        super().__init__()
        self.logger = logger

    def run(self):
        try:
            count = self.logger.capture_snapshot()
            self.done.emit(count)
        except Exception:
            self.done.emit(0)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.db.init_db()
        self.db.delete("threat_found", "status='已处理' OR status='handled'")
        self.connection_logger = ConnectionLogger()
        self.threat_count = 0
        self._auto_log_worker = None

        self.show_preload_dialog()
        
        self.setup_status_bar()
        self.init_ui()
        self.setup_menu()

        self.auto_log_timer = QTimer(self)
        self.auto_log_timer.timeout.connect(self.auto_capture_logs)
        self.auto_log_timer.start(120000)

    def show_preload_dialog(self):
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QProgressBar
        
        dialog = QDialog(self)
        dialog.setWindowTitle("危险外联排查工具")
        dialog.setModal(True)
        dialog.setFixedSize(400, 180)
        dialog.setStyleSheet("""
            QDialog { background: #0d1b3e; border-radius: 10px; }
            QLabel { color: #fff; font-size: 14px; }
            QProgressBar { 
                border: none; 
                background: #1a2a5c; 
                border-radius: 5px; 
                height: 8px;
            }
            QProgressBar::chunk { 
                background: #e94560; 
                border-radius: 5px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        title_label = QLabel("危险外联排查工具 v1.0")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e94560;")
        layout.addWidget(title_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.progress_label = QLabel("正在初始化...")
        layout.addWidget(self.progress_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        dialog.show()
        
        self.preload_worker = PreloadWorker(self.db)
        self.preload_worker.progress.connect(self.on_preload_progress)
        self.preload_worker.done.connect(dialog.accept)
        self.preload_worker.start()
        
        dialog.exec()

    def on_preload_progress(self, message):
        self.progress_label.setText(message)
        if message == "正在初始化数据库...":
            self.progress_bar.setValue(5)
        elif message == "正在扫描VPN/代理软件...":
            self.progress_bar.setValue(15)
        elif message == "正在捕获网络连接...":
            self.progress_bar.setValue(25)
        elif message == "正在检测进程...":
            self.progress_bar.setValue(35)
        elif message == "正在扫描启动项...":
            self.progress_bar.setValue(45)
        elif message == "正在检测用户账户...":
            self.progress_bar.setValue(55)
        elif message == "正在扫描已安装程序...":
            self.progress_bar.setValue(70)
        elif message == "正在初始化情报数据...":
            self.progress_bar.setValue(85)
        elif message == "加载完成":
            self.progress_bar.setValue(100)

    def init_ui(self):
        self.setWindowTitle("危险外联排查工具 v1.0")
        self.setMinimumSize(1200, 800)
        self.setStyleSheet(MAIN_STYLE)

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        self.dashboard_tab = DashboardTab(self)
        self.process_tab = ProcessTab(self)
        self.connection_tab = ConnectionTab(self)
        self.threat_intel_tab = ThreatIntelTab(self)
        self.startup_tab = StartupTab(self)
        self.user_tab = UserTab(self)
        self.report_tab = ReportTab(self)
        self.log_tab = LogTab(self)
        self.software_tab = SoftwareTab(self)

        self.tab_widget.addTab(self.dashboard_tab, "仪表盘")
        self.tab_widget.addTab(self.process_tab, "进程管理")
        self.tab_widget.addTab(self.connection_tab, "外联日志")
        self.tab_widget.addTab(self.threat_intel_tab, "情报同步")
        self.tab_widget.addTab(self.startup_tab, "启动项")
        self.tab_widget.addTab(self.user_tab, "用户账户")
        self.tab_widget.addTab(self.log_tab, "日志查看")
        self.tab_widget.addTab(self.software_tab, "程序查看")
        self.tab_widget.addTab(self.report_tab, "扫描报告")

        self.setCentralWidget(self.tab_widget)

    def setup_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件")
        switch_tab_action = QAction("切换标签页", self)
        switch_tab_action.setShortcut("Ctrl+Tab")
        switch_tab_action.triggered.connect(self.switch_tab)
        file_menu.addAction(switch_tab_action)

        file_menu.addSeparator()

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menubar.addMenu("视图")
        refresh_action = QAction("刷新当前页面", self)
        refresh_action.setShortcut("Ctrl+R")
        refresh_action.triggered.connect(self.refresh_current_tab)
        view_menu.addAction(refresh_action)

        help_menu = menubar.addMenu("帮助")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_process_label = QLabel("进程: -")
        self.status_bar.addWidget(self.status_process_label)

        self.status_threat_label = QLabel("威胁: -")
        self.status_bar.addWidget(self.status_threat_label)

        self.status_connection_label = QLabel("连接: -")
        self.status_bar.addWidget(self.status_connection_label)

        self.status_time_label = QLabel("")
        self.status_bar.addPermanentWidget(self.status_time_label)

        self.time_timer = QTimer(self)
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)
        self.update_time()

    def update_time(self):
        from datetime import datetime
        self.status_time_label.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def on_tab_changed(self, index):
        if hasattr(self, '_pending_activate_timer'):
            self._pending_activate_timer.stop()
        current_tab = self.tab_widget.currentWidget()
        if hasattr(current_tab, 'on_activate'):
            self._pending_activate_timer = QTimer(self)
            self._pending_activate_timer.setSingleShot(True)
            self._pending_activate_timer.timeout.connect(current_tab.on_activate)
            self._pending_activate_timer.start(50)

    def switch_tab(self):
        current = self.tab_widget.currentIndex()
        next_index = (current + 1) % self.tab_widget.count()
        self.tab_widget.setCurrentIndex(next_index)

    def refresh_current_tab(self):
        if hasattr(self, '_pending_activate_timer'):
            self._pending_activate_timer.stop()
        current_tab = self.tab_widget.currentWidget()
        if hasattr(current_tab, 'on_activate'):
            current_tab.on_activate()

    def auto_capture_logs(self):
        if self._auto_log_worker and self._auto_log_worker.isRunning():
            return
        self._auto_log_worker = AutoLogWorker(self.connection_logger)
        self._auto_log_worker.done.connect(self._on_auto_log_done)
        self._auto_log_worker.start()

    def _on_auto_log_done(self, count):
        if count > 0:
            self.status_connection_label.setText(f"连接: +{count}")

    def show_about(self):
        show_about(self, "危险外联排查工具 v1.0",
            "功能特性:\n"
            "  - 进程监控与异常检测\n"
            "  - 启动项检测\n"
            "  - 用户账户管理\n"
            "  - 外联日志记录与恶意IP识别\n"
            "  - 扫描报告导出\n\n"
            "建议以管理员身份运行以获得最佳效果"
        )

    def closeEvent(self, event):
        reply = show_question(self, "确认退出",
            "确定要退出程序吗？")
        if reply == QMessageBox.StandardButton.Yes:
            self.db.close()
            event.accept()
        else:
            event.ignore()
