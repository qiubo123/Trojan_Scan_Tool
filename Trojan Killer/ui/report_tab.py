import os
import re
import subprocess
import winreg
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QGroupBox, QMessageBox,
    QFileDialog, QSplitter, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont

from core.db import DatabaseManager
from core.process_monitor import ProcessMonitor
from core.user_checker import UserChecker
from .msg_box import show_info, show_critical


def _show_success_box(title, text, parent=None):
    from PyQt6.QtWidgets import QMessageBox, QLabel
    from PyQt6.QtCore import Qt
    msg = QMessageBox(parent) if parent else QMessageBox()
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle(title)
    msg.setText(text)
    layout = msg.layout()
    if layout:
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), QLabel):
                label = item.widget()
                label.setWordWrap(True)
                label.setAlignment(Qt.AlignmentFlag.AlignLeft)
                label.setMinimumWidth(550)
                break
    msg.setMinimumWidth(650)
    msg.exec()


def _html_escape(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")


def _get_installed_programs():
    programs = []
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

                    try:
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    except FileNotFoundError:
                        version = ""

                    try:
                        publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                    except FileNotFoundError:
                        publisher = ""

                    try:
                        install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                        if install_date and len(install_date) == 8:
                            install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:]}"
                    except FileNotFoundError:
                        install_date = ""

                    programs.append({
                        "name": name,
                        "version": version,
                        "publisher": publisher,
                        "install_date": install_date,
                    })
                    winreg.CloseKey(subkey)
                except (FileNotFoundError, OSError):
                    continue
            winreg.CloseKey(key)
        except FileNotFoundError:
            continue

    try:
        result = subprocess.run(
            ["wmic", "product", "get", "name,version,vendor,installdate"],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        output = result.stdout.decode("utf-8", errors="replace")
        for line in output.split("\n")[1:]:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"\s{2,}", line)
            if parts and parts[0] and parts[0] not in seen:
                seen.add(parts[0])
                programs.append({
                    "name": parts[0],
                    "version": parts[1] if len(parts) > 1 else "",
                    "publisher": parts[2] if len(parts) > 2 else "",
                    "install_date": parts[3] if len(parts) > 3 else "",
                })
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass

    programs.sort(key=lambda x: x["name"].lower())
    return programs


class ThreatsWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            threats = [dict(r) for r in self.db.fetch_all(
                "SELECT * FROM threat_found ORDER BY found_time DESC LIMIT 500"
            )]
            vpn_count = sum(1 for t in threats if t.get("threat_type") == "VPN/代理软件")
            self.data_ready.emit({"threats": threats, "vpn_count": vpn_count})
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class MaliciousLogsWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            logs = [dict(r) for r in self.db.fetch_all(
                "SELECT * FROM connection_log WHERE is_malicious=1 ORDER BY log_time DESC LIMIT 200"
            )]
            self.data_ready.emit({"malicious_logs": logs})
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class UsersWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            accounts = [dict(r) for r in self.db.fetch_all(
                "SELECT * FROM user_accounts ORDER BY scan_time DESC LIMIT 100"
            )]
            self.data_ready.emit({"user_accounts": accounts})
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class SysInfoWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def run(self):
        try:
            sys_info = self.monitor.get_system_info()
            self.data_ready.emit({"sys_info": sys_info})
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ReportTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.db = DatabaseManager()
        self.monitor = ProcessMonitor()

        self._activated = False
        self._pending_refresh = False
        self._workers = []
        self._partial_data = {}
        self.report_worker = None
        self._current_data = {}
        self._value_labels = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.refresh_btn = QPushButton("刷新报告")
        self.refresh_btn.clicked.connect(self.refresh_records)
        toolbar.addWidget(self.refresh_btn)

        self.export_html_btn = QPushButton("导出HTML报告")
        self.export_html_btn.clicked.connect(self.export_html)
        toolbar.addWidget(self.export_html_btn)

        self.export_txt_btn = QPushButton("导出TXT报告")
        self.export_txt_btn.clicked.connect(self.export_txt)
        toolbar.addWidget(self.export_txt_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(10)

        self.total_card, self._value_labels["total"] = self._create_card("威胁总数", "0", "#e94560")
        summary_layout.addWidget(self.total_card)

        self.high_card, self._value_labels["high"] = self._create_card("高危威胁", "0", "#e94560")
        summary_layout.addWidget(self.high_card)

        self.middle_card, self._value_labels["middle"] = self._create_card("中危威胁", "0", "#f39c12")
        summary_layout.addWidget(self.middle_card)

        self.low_card, self._value_labels["low"] = self._create_card("低危威胁", "0", "#27ae60")
        summary_layout.addWidget(self.low_card)

        layout.addLayout(summary_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)

        threat_group = QGroupBox("威胁详情")
        threat_layout = QVBoxLayout(threat_group)
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(7)
        self.threat_table.setHorizontalHeaderLabels([
            "威胁类型", "名称", "路径/IP", "风险等级", "进程", "描述", "发现时间"
        ])
        self.threat_table.horizontalHeader().setStretchLastSection(True)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.threat_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        threat_layout.addWidget(self.threat_table)
        splitter.addWidget(threat_group)

        stats_group = QGroupBox("统计分析")
        stats_layout = QHBoxLayout(stats_group)

        self.type_stats_text = QTextEdit()
        self.type_stats_text.setReadOnly(True)
        self.type_stats_text.setMaximumWidth(400)
        stats_layout.addWidget(self.type_stats_text)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        stats_layout.addWidget(self.summary_text)

        splitter.addWidget(stats_group)

        layout.addWidget(splitter)

    def _create_card(self, title, value, color):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 11px; color: #a0a0a0; font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title_label)
        value_label = QLabel(value)
        value_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color}; font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(value_label)
        card.setMinimumWidth(140)
        return card, value_label

    def refresh_records(self):
        if self._pending_refresh:
            return

        self._pending_refresh = True
        self._workers = []
        self._partial_data = {}

        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("加载中...")

        def try_combine_data():
            if len(self._partial_data) < 4:
                return
            self._combine_and_update()

        def on_threats(data):
            if "error" in data:
                print(f"加载威胁数据失败: {data['error']}")
                self._partial_data["threats_done"] = True
                self._partial_data.setdefault("threats", [])
                self._partial_data["vpn_count"] = 0
            else:
                self._partial_data["threats"] = data["threats"]
                self._partial_data["vpn_count"] = data["vpn_count"]
            self._partial_data["threats_done"] = True
            try_combine_data()

        def on_logs(data):
            if "error" in data:
                print(f"加载日志数据失败: {data['error']}")
                self._partial_data["malicious_logs"] = []
            else:
                self._partial_data["malicious_logs"] = data["malicious_logs"]
            self._partial_data["logs_done"] = True
            try_combine_data()

        def on_users(data):
            if "error" in data:
                print(f"加载用户数据失败: {data['error']}")
                self._partial_data["user_accounts"] = []
            else:
                self._partial_data["user_accounts"] = data["user_accounts"]
            self._partial_data["users_done"] = True
            try_combine_data()

        def on_sysinfo(data):
            if "error" in data:
                print(f"加载系统信息失败: {data['error']}")
                self._partial_data["sys_info"] = {}
            else:
                self._partial_data["sys_info"] = data["sys_info"]
            self._partial_data["sysinfo_done"] = True
            try_combine_data()

        w1 = ThreatsWorker(self.db)
        w1.data_ready.connect(on_threats)
        self._workers.append(w1)

        w2 = MaliciousLogsWorker(self.db)
        w2.data_ready.connect(on_logs)
        self._workers.append(w2)

        w3 = UsersWorker(self.db)
        w3.data_ready.connect(on_users)
        self._workers.append(w3)

        w4 = SysInfoWorker(self.monitor)
        w4.data_ready.connect(on_sysinfo)
        self._workers.append(w4)

        for w in self._workers:
            w.start()

    def _combine_and_update(self):
        self._pending_refresh = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新报告")

        threats = self._partial_data.get("threats", [])
        malicious_logs = self._partial_data.get("malicious_logs", [])
        user_accounts = self._partial_data.get("user_accounts", [])
        if not user_accounts:
            try:
                UserChecker().get_all_users()
                user_accounts = [dict(r) for r in self.db.fetch_all(
                    "SELECT * FROM user_accounts ORDER BY scan_time DESC LIMIT 100"
                )]
            except Exception:
                pass
        sys_info = self._partial_data.get("sys_info", {})

        suspicious_users_data = [u for u in user_accounts if u.get('is_suspicious', 0) == 1]
        for u in suspicious_users_data:
            threats.append({
                "threat_type": "可疑账户",
                "threat_name": u.get('name', ''),
                "threat_path": u.get('full_name', ''),
                "threat_ip": "",
                "risk_level": "中危",
                "process_name": u.get('name', ''),
                "description": u.get('suspicious_reason', '可疑账户'),
                "found_time": u.get('scan_time', ''),
                "status": "未处理"
            })

        for log in malicious_logs:
            threats.append({
                "threat_type": "恶意连接",
                "threat_name": f"连接到 {log.get('remote_ip', '')}:{log.get('remote_port', '')}",
                "threat_path": "",
                "threat_ip": log.get('remote_ip', ''),
                "risk_level": "高危",
                "process_name": log.get('process_name', ''),
                "description": f"本地: {log.get('local_ip', '')}:{log.get('local_port', '')} | 协议: {log.get('protocol', '')}",
                "found_time": log.get('log_time', ''),
                "status": "未处理"
            })

        total = len(threats)
        high = sum(1 for t in threats if t["risk_level"] in ("高危", "high"))
        middle = sum(1 for t in threats if t["risk_level"] in ("中危", "middle"))
        low = sum(1 for t in threats if t["risk_level"] in ("低危", "low"))
        type_stats = {}
        for t in threats:
            tp = t["threat_type"] or "未知"
            type_stats[tp] = type_stats.get(tp, 0) + 1

        data = {
            "threats": threats,
            "total": total,
            "high": high,
            "middle": middle,
            "low": low,
            "type_stats": type_stats,
            "sys_info": sys_info,
            "users": user_accounts,
            "suspicious_users": suspicious_users_data,
            "normal_user_count": sum(1 for u in user_accounts if u.get('is_suspicious', 0) == 0),
            "suspicious_user_count": len(suspicious_users_data),
            "vpn_count": self._partial_data.get("vpn_count", 0),
            "vpn_extensions": [],
            "vpn_programs": [],
            "proxy_settings": [],
            "malicious_logs": malicious_logs,
            "malicious_log_count": len(malicious_logs),
            "programs": [],
            "processes": [],
        }

        self._update_ui(data)

    def _update_ui(self, data):
        self._current_data = data
        threats = data["threats"]

        self._value_labels["total"].setText(str(data["total"]))
        self._value_labels["high"].setText(str(data["high"]))
        self._value_labels["middle"].setText(str(data["middle"]))
        self._value_labels["low"].setText(str(data["low"]))

        risk_order = {"高危": 0, "high": 0, "中危": 1, "middle": 1, "低危": 2, "low": 2}
        sorted_threats = sorted(threats, key=lambda x: (risk_order.get(x["risk_level"], 3), x["threat_name"].lower()))
        
        self.threat_table.setUpdatesEnabled(False)
        self.threat_table.setRowCount(len(sorted_threats))
        for i, t in enumerate(sorted_threats):
            self.threat_table.setItem(i, 0, QTableWidgetItem(t["threat_type"]))
            self.threat_table.setItem(i, 1, QTableWidgetItem(t["threat_name"]))
            path = t["threat_path"] or t["threat_ip"] or ""
            self.threat_table.setItem(i, 2, QTableWidgetItem(path))

            risk_item = QTableWidgetItem(t["risk_level"])
            if t["risk_level"] in ("高危", "high"):
                risk_item.setForeground(QBrush(QColor("#e94560")))
            elif t["risk_level"] in ("中危", "middle"):
                risk_item.setForeground(QBrush(QColor("#f39c12")))
            else:
                risk_item.setForeground(QBrush(QColor("#27ae60")))
            self.threat_table.setItem(i, 3, risk_item)

            self.threat_table.setItem(i, 4, QTableWidgetItem(t["process_name"]))
            self.threat_table.setItem(i, 5, QTableWidgetItem(t["description"]))
            self.threat_table.setItem(i, 6, QTableWidgetItem(t["found_time"]))
        self.threat_table.setUpdatesEnabled(True)

        type_stats = data["type_stats"]
        type_html = "<h3>威胁类型分布</h3>"
        type_html += '<table style="width:100%;border-collapse:collapse;">'
        type_html += '<tr style="background:#0f3460;"><th style="padding:6px;text-align:left;">类型</th><th style="padding:6px;text-align:right;">数量</th></tr>'
        sorted_types = sorted(type_stats.items(), key=lambda x: x[1], reverse=True)
        for tp, cnt in sorted_types:
            type_html += f'<tr><td style="padding:4px 6px;border-bottom:1px solid #0f3460;">{_html_escape(tp)}</td><td style="padding:4px 6px;border-bottom:1px solid #0f3460;text-align:right;color:#e94560;">{cnt}</td></tr>'
        type_html += "</table>"
        self.type_stats_text.setHtml(type_html)

        summary_html = "<h3>综合评估</h3>"
        total = data["total"]
        high = data["high"]
        middle = data["middle"]
        low = data["low"]
        sys = data.get("sys_info", {})
        vpn_count = data.get("vpn_count", 0)
        malicious_log_count = data.get("malicious_log_count", 0)
        suspicious_user_count = data.get("suspicious_user_count", 0)
        normal_user_count = data.get('normal_user_count', 0)
        ip_addresses = ', '.join(i['address'] for i in sys.get('ip_addresses', [])) or 'N/A'
        mac_addresses = ', '.join(m['address'] for m in sys.get('mac_addresses', [])) or 'N/A'
        
        summary_html += f"<p><b>系统信息:</b> {_html_escape(sys.get('os_version', 'N/A'))} | 主机: {_html_escape(sys.get('hostname', 'N/A'))} | IP: {_html_escape(ip_addresses)} | MAC: {_html_escape(mac_addresses)}</p>"
        summary_html += f"<p><b>账户安全:</b> 共 {normal_user_count + suspicious_user_count} 个账户，其中可疑账户 {suspicious_user_count} 个</p>"
        summary_html += f"<p><b>网络安全:</b> 检测到恶意连接 {malicious_log_count} 条，涉及 VPN/代理软件 {vpn_count} 个</p>"
        
        if total == 0:
            summary_html += "<p style='color:#27ae60;'><b>✓ 安全状态：</b>本次扫描未发现安全威胁，系统运行状态良好。</p>"
        else:
            summary_html += f"<p style='color:#e94560;'><b>⚠ 安全警告：</b>本次扫描共发现 <b>{total}</b> 个安全威胁，详情如下：</p>"
            summary_html += "<ul>"
            if high > 0:
                summary_html += f"<li style='color:#e94560;'><b>高危威胁 {high} 个</b>：包含恶意连接、可疑进程等，建议立即处理</li>"
            if middle > 0:
                summary_html += f"<li style='color:#f39c12;'><b>中危威胁 {middle} 个</b>：包含可疑账户、VPN代理软件等，建议尽快处理</li>"
            if low > 0:
                summary_html += f"<li style='color:#27ae60;'><b>低危威胁 {low} 个</b>：包含浏览器劫持等，可酌情处理</li>"
            summary_html += "</ul>"
            
            summary_html += "<p><b>威胁类型分布：</b></p>"
            summary_html += '<table style="width:100%;border-collapse:collapse;">'
            summary_html += '<tr style="background:#0f3460;"><th style="padding:6px;text-align:left;">威胁类型</th><th style="padding:6px;text-align:right;">数量</th></tr>'
            sorted_types = sorted(data["type_stats"].items(), key=lambda x: x[1], reverse=True)
            for tp, cnt in sorted_types:
                summary_html += f'<tr><td style="padding:4px 6px;border-bottom:1px solid #0f3460;">{_html_escape(tp)}</td><td style="padding:4px 6px;border-bottom:1px solid #0f3460;text-align:right;color:#e94560;">{cnt}</td></tr>'
            summary_html += "</table>"
        self.summary_text.setHtml(summary_html)

    def on_activate(self):
        if not self._activated:
            self._activated = True
            self.refresh_records()

    def _build_report_data(self):
        threats = self.db.fetch_all(
            "SELECT * FROM threat_found ORDER BY found_time DESC LIMIT 500"
        )

        vpn_count = sum(1 for t in threats if t["threat_type"] == "VPN/代理软件")

        malicious_logs = self.db.fetch_all(
            "SELECT * FROM connection_log WHERE is_malicious=1 ORDER BY log_time DESC LIMIT 200"
        )
        
        user_accounts = [dict(r) for r in self.db.fetch_all(
            "SELECT * FROM user_accounts ORDER BY scan_time DESC LIMIT 100"
        )]
        if not user_accounts:
            try:
                UserChecker().get_all_users()
                user_accounts = [dict(r) for r in self.db.fetch_all(
                    "SELECT * FROM user_accounts ORDER BY scan_time DESC LIMIT 100"
                )]
            except Exception:
                pass
        
        software_info = [dict(r) for r in self.db.fetch_all(
            "SELECT * FROM software_info ORDER BY scan_time DESC LIMIT 500"
        )]
        
        process_info = [dict(r) for r in self.db.fetch_all(
            "SELECT * FROM process_info ORDER BY scan_time DESC LIMIT 500"
        )]
        
        suspicious_users_data = [u for u in user_accounts if u.get('is_suspicious', 0) == 1]
        for u in suspicious_users_data:
            threats.append({
                "threat_type": "可疑账户",
                "threat_name": u.get('name', ''),
                "threat_path": u.get('full_name', ''),
                "threat_ip": "",
                "risk_level": "中危",
                "process_name": u.get('name', ''),
                "description": u.get('suspicious_reason', '可疑账户'),
                "found_time": u.get('scan_time', ''),
                "status": "未处理"
            })
        
        malicious_logs_data = [dict(r) for r in malicious_logs]
        for log in malicious_logs_data:
            threats.append({
                "threat_type": "恶意连接",
                "threat_name": f"连接到 {log.get('remote_ip', '')}:{log.get('remote_port', '')}",
                "threat_path": "",
                "threat_ip": log.get('remote_ip', ''),
                "risk_level": "高危",
                "process_name": log.get('process_name', ''),
                "description": f"本地: {log.get('local_ip', '')}:{log.get('local_port', '')} | 协议: {log.get('protocol', '')}",
                "found_time": log.get('log_time', ''),
                "status": "未处理"
            })

        total = len(threats)
        high = sum(1 for t in threats if t["risk_level"] in ("高危", "high"))
        middle = sum(1 for t in threats if t["risk_level"] in ("中危", "middle"))
        low = sum(1 for t in threats if t["risk_level"] in ("低危", "low"))
        type_stats = {}
        for t in threats:
            tp = t["threat_type"] or "未知"
            type_stats[tp] = type_stats.get(tp, 0) + 1

        vpn_threats = [t for t in threats if t["threat_type"] == "VPN/代理软件"]
        vpn_extensions = []
        vpn_programs = []
        proxy_settings = []
        
        for threat in vpn_threats:
            desc = threat["description"] or ""
            if "浏览器插件" in desc:
                browser = ""
                reason = ""
                if "|" in desc:
                    parts = desc.split("|")
                    for part in parts:
                        if "浏览器" in part:
                            browser = part.replace("浏览器插件:", "").strip()
                        else:
                            reason = part.strip()
                vpn_extensions.append({
                    "name": threat["threat_name"],
                    "browser": browser,
                    "path": threat["threat_path"],
                    "reason": reason or desc
                })
            elif "系统代理" in threat["threat_name"] or "代理设置" in threat["threat_name"]:
                proxy_settings.append({
                    "type": threat["threat_name"],
                    "status": desc.split("|")[0].strip() if "|" in desc else "",
                    "details": desc.split("|")[1].strip() if "|" in desc and len(desc.split("|")) > 1 else ""
                })
            else:
                vpn_programs.append({
                    "name": threat["threat_name"],
                    "version": "",
                    "publisher": "",
                    "install_date": "",
                    "reason": desc
                })
        
        sys_info = self.monitor.get_system_info()
        
        normal_user_count = sum(1 for u in user_accounts if u.get('is_suspicious', 0) == 0)
        suspicious_user_count = sum(1 for u in user_accounts if u.get('is_suspicious', 0) == 1)

        return {
            "threats": threats,
            "total": total,
            "high": high,
            "middle": middle,
            "low": low,
            "type_stats": type_stats,
            "sys_info": sys_info,
            "users": user_accounts,
            "suspicious_users": [u for u in user_accounts if u.get('is_suspicious', 0) == 1],
            "normal_user_count": normal_user_count,
            "suspicious_user_count": suspicious_user_count,
            "vpn_count": vpn_count,
            "vpn_extensions": vpn_extensions,
            "vpn_programs": vpn_programs,
            "proxy_settings": proxy_settings,
            "malicious_logs": [dict(r) for r in malicious_logs],
            "malicious_log_count": len(malicious_logs),
            "programs": software_info,
            "processes": process_info,
        }

    def export_html(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出HTML报告", f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML文件 (*.html)"
        )
        if not filepath:
            return

        try:
            d = self._build_report_data()
            threats = d["threats"]
            total = d["total"]
            high = d["high"]
            middle = d["middle"]
            low = d["low"]
            type_stats = d["type_stats"]
            sys = d["sys_info"]
            users = d.get("users", [])

            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            type_rows = ""
            sorted_types = sorted(type_stats.items(), key=lambda x: x[1], reverse=True)
            for tp, cnt in sorted_types:
                pct = round(cnt / total * 100, 1) if total > 0 else 0
                type_rows += f"<tr><td>{_html_escape(tp)}</td><td>{cnt}</td><td>{pct}%</td></tr>\n"

            threat_rows = ""
            for t in threats:
                level_class = "high" if t["risk_level"] in ("高危", "high") else ("middle" if t["risk_level"] in ("中危", "middle") else "low")
                path = t["threat_path"] or t["threat_ip"] or ""
                threat_rows += f"<tr><td>{_html_escape(t['threat_type'])}</td><td>{_html_escape(t['threat_name'])}</td><td>{_html_escape(path)}</td><td class='{level_class}'>{_html_escape(t['risk_level'])}</td><td>{_html_escape(t['process_name'])}</td><td>{_html_escape(t['description'])}</td><td>{_html_escape(t['found_time'])}</td></tr>\n"

            all_user_rows = ""
            for u in users:
                is_suspicious = '是' if u.get('is_suspicious', 0) == 1 else '否'
                is_admin = '是' if u.get('is_admin', 0) == 1 else '否'
                name = str(u.get('name', '') or '')
                full_name = str(u.get('full_name', '') or '')
                status = str(u.get('status', '') or '')
                last_login = str(u.get('last_login', '') or '')
                all_user_rows += f"<tr><td>{_html_escape(name)}</td><td>{_html_escape(full_name)}</td><td>{_html_escape(is_admin)}</td><td>{_html_escape(is_suspicious)}</td><td>{_html_escape(status)}</td><td>{_html_escape(last_login)}</td></tr>\n"

            ip_addresses = ', '.join(i['address'] for i in sys.get('ip_addresses', [])) if sys.get('ip_addresses') else 'N/A'
            mac_addresses = ', '.join(m['address'] for m in sys.get('mac_addresses', [])) if sys.get('mac_addresses') else 'N/A'

            html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全扫描报告</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; background: #f5f6fa; color: #2c3e50; padding: 30px; }}
.container {{ max-width: 1200px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); padding: 40px; }}
.header {{ text-align: center; padding-bottom: 30px; border-bottom: 3px solid #e94560; margin-bottom: 30px; }}
.header h1 {{ color: #e94560; font-size: 28px; margin-bottom: 8px; }}
.header p {{ color: #7f8c8d; font-size: 14px; }}
.summary-cards {{ display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }}
.card {{ flex: 1; min-width: 140px; background: #f8f9fa; border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid #e94560; }}
.card h3 {{ font-size: 13px; color: #7f8c8d; margin-bottom: 8px; }}
.card .value {{ font-size: 32px; font-weight: bold; }}
.card.high {{ border-left-color: #e94560; }}
.card.middle {{ border-left-color: #f39c12; }}
.card.low {{ border-left-color: #27ae60; }}
.section {{ margin-bottom: 30px; }}
.section h2 {{ font-size: 20px; color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-bottom: 15px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid #e0e0e0; font-size: 13px; word-wrap: break-word; overflow-wrap: break-word; }}
th {{ background: #f8f9fa; color: #7f8c8d; font-weight: 600; }}
tr:hover {{ background: #f5f6fa; }}
.high {{ color: #e94560; font-weight: bold; }}
.middle {{ color: #f39c12; font-weight: bold; }}
.low {{ color: #27ae60; font-weight: bold; }}
.footer {{ text-align: center; color: #bdc3c7; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>安全扫描报告</h1>
<p>报告生成时间: {now_str}</p>
</div>

<div class="summary-cards">
<div class="card high"><h3>威胁总数</h3><div class="value">{total}</div></div>
<div class="card high"><h3>高危威胁</h3><div class="value">{high}</div></div>
<div class="card middle"><h3>中危威胁</h3><div class="value">{middle}</div></div>
<div class="card low"><h3>低危威胁</h3><div class="value">{low}</div></div>
</div>

<div class="section">
<h2>系统信息</h2>
<table>
<tr><th>项目</th><th>值</th></tr>
<tr><td>系统版本</td><td>{_html_escape(sys.get('os_version', 'N/A'))}</td></tr>
<tr><td>主机名</td><td>{_html_escape(sys.get('hostname', 'N/A'))}</td></tr>
<tr><td>IP地址</td><td>{_html_escape(ip_addresses)}</td></tr>
<tr><td>MAC地址</td><td>{_html_escape(mac_addresses)}</td></tr>
<tr><td>系统启动时间</td><td>{_html_escape(sys.get('boot_time', 'N/A'))}</td></tr>
<tr><td>CPU核心数</td><td>{sys.get('cpu_count', 0)}</td></tr>
<tr><td>内存</td><td>{sys.get('memory_used', 0)}GB / {sys.get('memory_total', 0)}GB</td></tr>
<tr><td>运行进程数</td><td>{sys.get('process_count', 0)}</td></tr>
</table>
</div>

<div class="section">
<h2>威胁类型分布</h2>
<table>
<thead><tr><th>威胁类型</th><th>数量</th><th>占比</th></tr></thead>
<tbody>
{type_rows}
</tbody>
</table>
</div>

<div class="section">
<h2>威胁详情列表</h2>
<div style="overflow-x: auto;">
<table>
<colgroup>
<col style="width:10%;"><col style="width:18%;"><col style="width:22%;"><col style="width:8%;"><col style="width:14%;"><col style="width:28%;">
</colgroup>
<thead><tr><th>威胁类型</th><th>名称</th><th>路径/IP</th><th>风险等级</th><th>进程</th><th>描述</th><th>发现时间</th></tr></thead>
<tbody>
{threat_rows}
</tbody>
</table>
</div>
</div>

<div class="section">
<h2>所有用户账户 ({len(users)} 个)</h2>
<div style="overflow-x: auto;">
<table>
<thead><tr><th>用户名</th><th>全名</th><th>管理员</th><th>可疑</th><th>状态</th><th>最后登录</th></tr></thead>
<tbody>
{all_user_rows}
</tbody>
</table>
</div>
</div>

<div class="footer">
<p>本报告由危险外联排查工具自动生成</p>
</div>
</div>
</body>
</html>"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            _show_success_box("导出成功", f"HTML报告已导出到:\n{filepath}", self)
        except Exception as e:
            show_critical(self, "导出失败", f"导出HTML报告时出错:\n{str(e)}")

    def export_txt(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出TXT报告", f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "文本文件 (*.txt)"
        )
        if not filepath:
            return

        try:
            d = self._build_report_data()
            threats = d["threats"]
            total = d["total"]
            high = d["high"]
            middle = d["middle"]
            low = d["low"]
            type_stats = d["type_stats"]
            sys = d["sys_info"]
            suspicious_users = d["suspicious_users"]
            programs = d.get("programs", [])
            malicious_logs = d["malicious_logs"]
            users = d.get("users", [])
            processes = d.get("processes", [])

            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sep = "=" * 70
            sub_sep = "-" * 70

            ip_addresses = ', '.join(i['address'] for i in sys.get('ip_addresses', [])) if sys.get('ip_addresses') else 'N/A'
            mac_addresses = ', '.join(m['address'] for m in sys.get('mac_addresses', [])) if sys.get('mac_addresses') else 'N/A'

            lines = []
            lines.append(sep)
            lines.append("                    安全扫描报告")
            lines.append(sep)
            lines.append(f"报告生成时间: {now_str}")
            lines.append("")

            lines.append(sub_sep)
            lines.append("【系统信息】")
            lines.append(sub_sep)
            lines.append(f"  系统版本: {sys.get('os_version', 'N/A')}")
            lines.append(f"  主机名: {sys.get('hostname', 'N/A')}")
            lines.append(f"  IP地址: {ip_addresses}")
            lines.append(f"  MAC地址: {mac_addresses}")
            lines.append(f"  启动时间: {sys.get('boot_time', 'N/A')}")
            lines.append(f"  CPU核心数: {sys.get('cpu_count', 0)}")
            lines.append(f"  内存: {sys.get('memory_used', 0)}GB / {sys.get('memory_total', 0)}GB")
            lines.append(f"  运行进程数: {sys.get('process_count', 0)}")
            lines.append("")

            lines.append(sub_sep)
            lines.append("【威胁统计摘要】")
            lines.append(sub_sep)
            lines.append(f"  威胁总数: {total}")
            lines.append(f"  高危威胁: {high}")
            lines.append(f"  中危威胁: {middle}")
            lines.append(f"  低危威胁: {low}")
            lines.append("")

            lines.append(sub_sep)
            lines.append("【威胁类型分布】")
            lines.append(sub_sep)
            sorted_types = sorted(type_stats.items(), key=lambda x: x[1], reverse=True)
            for tp, cnt in sorted_types:
                pct = round(cnt / total * 100, 1) if total > 0 else 0
                bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                lines.append(f"  {tp:12s} | {cnt:4d} | {pct:5.1f}% | {bar}")
            lines.append("")

            lines.append(sub_sep)
            lines.append("【威胁详情列表】")
            lines.append(sub_sep)
            header = f"{'威胁类型':12s} {'名称':20s} {'路径/IP':24s} {'风险等级':8s} {'进程':16s} {'发现时间':20s}"
            lines.append(header)
            lines.append("-" * len(header))
            for t in threats:
                path = t["threat_path"] or t["threat_ip"] or ""
                lines.append(f"{str(t['threat_type'] or ''):12s} {str(t['threat_name'] or ''):20s} {str(path):24s} {str(t['risk_level'] or ''):8s} {str(t['process_name'] or ''):16s} {str(t['found_time'] or ''):20s}")
            lines.append("")

            lines.append(sub_sep)
            lines.append(f"【所有用户账户 ({len(users)} 个)】")
            lines.append(sub_sep)
            if users:
                header2 = f"{'用户名':20s} {'全名':20s} {'管理员':6s} {'可疑':6s} {'状态':10s} {'最后登录':20s}"
                lines.append(header2)
                lines.append("-" * len(header2))
                for u in users:
                    is_suspicious = '是' if u.get('is_suspicious', 0) == 1 else '否'
                    is_admin = '是' if u.get('is_admin', 0) == 1 else '否'
                    lines.append(f"{str(u.get('name', '')):20s} {str(u.get('full_name', '')):20s} {is_admin:6s} {is_suspicious:6s} {str(u.get('status', '')):10s} {str(u.get('last_login', '')):20s}")
            else:
                lines.append("  未发现用户账户")
            lines.append("")

            lines.append(sub_sep)
            lines.append(f"【可疑用户账户 ({len(suspicious_users)} 个)】")
            lines.append(sub_sep)
            if suspicious_users:
                header3 = f"{'用户名':20s} {'全名':20s} {'状态':10s} {'原因':30s}"
                lines.append(header3)
                lines.append("-" * len(header3))
                for u in suspicious_users:
                    reasons = u.get('suspicious_reason', '可疑用户') or '可疑用户'
                    status = '已禁用' if u.get('status', '').lower() == 'disabled' else '正常'
                    lines.append(f"{str(u.get('name', '')):20s} {str(u.get('full_name', '')):20s} {status:10s} {reasons:30s}")
            else:
                lines.append("  未发现可疑用户")
            lines.append("")

            lines.append(sub_sep)
            lines.append(f"【恶意连接日志 ({len(malicious_logs)} 条)】")
            lines.append(sub_sep)
            if malicious_logs:
                header4 = f"{'时间':20s} {'本地IP':16s} {'端口':6s} {'远程IP':16s} {'端口':6s} {'PID':6s} {'进程名':16s} {'协议':6s} {'状态':8s}"
                lines.append(header4)
                lines.append("-" * len(header4))
                for log in malicious_logs:
                    lines.append(f"{str(log.get('log_time', '')):20s} {str(log.get('local_ip', '')):16s} {str(log.get('local_port', 0)):6s} {str(log.get('remote_ip', '')):16s} {str(log.get('remote_port', 0)):6s} {str(log.get('pid', 0)):6s} {str(log.get('process_name', '')):16s} {str(log.get('protocol', '')):6s} {str(log.get('status', '')):8s}")
            else:
                lines.append("  未发现恶意连接日志")
            lines.append("")

            lines.append(sub_sep)
            lines.append(f"【已安装程序 ({len(programs)} 个)】")
            lines.append(sub_sep)
            for p in programs:
                is_vpn = ' [VPN软件]' if p.get('is_vpn', 0) == 1 else ''
                lines.append(f"  {p.get('name', '')} | 版本: {p.get('version', '')} | 发布者: {p.get('publisher', '')} | 安装日期: {p.get('install_date', '')}{is_vpn}")
            lines.append("")

            lines.append(sub_sep)
            lines.append(f"【运行进程 ({len(processes)} 个)】")
            lines.append(sub_sep)
            for proc in processes:
                is_suspicious = ' [可疑]' if proc.get('suspicious', 0) == 1 else ''
                lines.append(f"  PID: {proc.get('pid', 0)} | 进程名: {proc.get('name', '')} | CPU: {proc.get('cpu_usage', 0)}% | 可疑: {is_suspicious}")
            lines.append("")

            lines.append(sep)
            lines.append("                    报告结束")
            lines.append(sep)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            _show_success_box("导出成功", f"TXT报告已导出到:\n{filepath}", self)
        except Exception as e:
            show_critical(self, "导出失败", f"导出TXT报告时出错:\n{str(e)}")
