from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QHeaderView, QGroupBox,
    QMessageBox, QDialog, QFormLayout, QSpinBox, QDialogButtonBox,
    QComboBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

import json
import os

from core.malicious_ip import MaliciousIPManager, get_machine_id
from core.db import get_data_dir
from .msg_box import show_warning, show_info, show_critical, show_question


class TestConnectionWorker(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, url, secret_key=""):
        super().__init__()
        self.url = url
        self.secret_key = secret_key

    def run(self):
        try:
            import urllib.request
            health_url = f"{self.url.rstrip('/')}/api/v1/health"
            if self.secret_key:
                import urllib.parse
                health_url += f"?key={urllib.parse.quote(self.secret_key)}"
            req = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            self.finished.emit(result)
        except Exception as e:
            self.finished.emit({"error": str(e)})


class AddBlackIPDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("添加恶意IP")
        self.setMinimumWidth(400)
        layout = QFormLayout(self)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("例如: 192.168.1.100")
        layout.addRow("IP地址:", self.ip_input)

        self.port_input = QSpinBox()
        self.port_input.setRange(0, 65535)
        self.port_input.setValue(0)
        self.port_input.setSpecialValueText("任意")
        layout.addRow("端口:", self.port_input)

        self.type_input = QLineEdit()
        self.type_input.setPlaceholderText("例如: C2服务器")
        layout.addRow("威胁类型:", self.type_input)

        self.location_input = QLineEdit()
        self.location_input.setPlaceholderText("例如: 中国北京、美国纽约")
        layout.addRow("归属地:", self.location_input)

        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("多个标签用逗号分隔")
        layout.addRow("标签:", self.tags_input)

        self.virus_input = QLineEdit()
        self.virus_input.setPlaceholderText("例如: RedLine窃密木马、Mirai僵尸网络")
        layout.addRow("关联病毒:", self.virus_input)

        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("描述信息")
        layout.addRow("描述:", self.desc_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_data(self):
        return {
            "ip": self.ip_input.text().strip(),
            "port": self.port_input.value(),
            "threat_type": self.type_input.text().strip(),
            "location": self.location_input.text().strip(),
            "tags": self.tags_input.text().strip(),
            "related_virus": self.virus_input.text().strip(),
            "description": self.desc_input.text().strip(),
        }


class BlacklistQueryWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, malicious_mgr, filters):
        super().__init__()
        self.malicious_mgr = malicious_mgr
        self.filters = filters

    def run(self):
        try:
            keyword = self.filters.get("keyword", "")
            threat_type = self.filters.get("threat_type", "")
            status = self.filters.get("status", "")
            ips = self.malicious_mgr.get_recent_black_ips(100)
            if keyword:
                ips = [ip for ip in ips if keyword in ip["ip"].lower()]
            if threat_type:
                ips = [ip for ip in ips if ip.get("threat_type", "") == threat_type]
            if status:
                ips = [ip for ip in ips if ip.get("status", "active") == status]
            self.data_ready.emit(ips)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class SyncConfigDialog(QDialog):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.setWindowTitle("情报同步配置")
        self.setMinimumWidth(500)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("例如: http://192.168.1.100:18080")
        self.url_input.setText(config.get("server_url", ""))
        form.addRow("服务器地址:", self.url_input)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("留空则不使用签名验证")
        self.key_input.setText(config.get("secret_key", ""))
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("API密钥:", self.key_input)

        self.client_id_input = QLineEdit()
        self.client_id_input.setPlaceholderText("留空则使用本机硬件ID")
        machine_id = get_machine_id()
        saved_id = config.get("client_id", "")
        if saved_id:
            self.client_id_input.setText(saved_id)
        else:
            self.client_id_input.setText(machine_id)
        self.client_id_input.setReadOnly(True)
        self.client_id_input.setStyleSheet("color: #888; font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;")
        form.addRow("客户端ID:", self.client_id_input)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("增量同步（默认）", "incremental")
        self.mode_combo.addItem("全量同步", "full")
        self.mode_combo.addItem("推送数据", "push")
        current_mode = config.get("sync_mode", "incremental")
        idx = self.mode_combo.findData(current_mode)
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)
        form.addRow("同步模式:", self.mode_combo)

        layout.addLayout(form)

        info_label = QLabel(
            "提示：\n"
            "• 增量同步：从服务器获取新增IP，更新字段数据。\n"
            "  不会向服务器推送本地数据，也不会删除本机IP。\n"
            "• 全量同步：完全和服务端的数据保持一致。\n"
            "  本机中来源为服务端的IP如果不存在于服务端，将被删除。\n"
            "• 推送数据：将本机的所有IP推送到服务端。\n"
            "  推送到服务端的数据需要管理员审核后才能生效。"
        )
        info_label.setStyleSheet("color: #888; font-size: 12px; padding: 8px; background: #1a1a2e; border-radius: 4px; font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        test_btn = QPushButton("测试连接")
        test_btn.clicked.connect(self.test_connection)
        btn_layout.addWidget(test_btn)
        save_btn = QPushButton("保存并同步")
        save_btn.setObjectName("primaryBtn")
        save_btn.clicked.connect(self.accept)
        btn_layout.addWidget(save_btn)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def get_config(self):
        return {
            "server_url": self.url_input.text().strip(),
            "secret_key": self.key_input.text().strip(),
            "client_id": self.client_id_input.text().strip(),
            "sync_mode": self.mode_combo.currentData(),
        }

    def test_connection(self):
        url = self.url_input.text().strip()
        if not url:
            show_warning(self, "提示", "请先输入服务器地址")
            return

        self.setEnabled(False)

        def on_test_finished(result):
            self.setEnabled(True)
            if "error" in result:
                show_critical(self, "连接失败", f"无法连接到服务器: {result['error']}")
                return
            if result.get("code") == 0:
                data = result.get("data", {})
                show_info(
                    self, "连接成功",
                    f"服务器状态: 运行中\n"
                    f"IP总数: {data.get('ip_count', 0)}\n"
                    f"客户端数: {data.get('client_count', 0)}\n"
                    f"版本: {data.get('version', 'N/A')}"
                )
            else:
                show_warning(self, "连接失败", f"服务器返回错误: {result.get('message', '未知错误')}")

        secret_key = self.key_input.text().strip()
        self._test_worker = TestConnectionWorker(url, secret_key)
        self._test_worker.finished.connect(on_test_finished)
        self._test_worker.start()


class ThreatIntelTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.malicious_mgr = MaliciousIPManager()
        self._activated = False
        self._refresh_in_progress = False

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._do_filter)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.clicked.connect(self.refresh_blacklist)
        toolbar.addWidget(self.refresh_btn)

        self.add_black_btn = QPushButton("添加黑名单")
        self.add_black_btn.clicked.connect(self.add_black_ip)
        toolbar.addWidget(self.add_black_btn)

        self.sync_btn = QPushButton("情报同步")
        self.sync_btn.setObjectName("primaryBtn")
        self.sync_btn.clicked.connect(self.sync_with_server)
        toolbar.addWidget(self.sync_btn)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索IP地址...")
        self.search_input.setMinimumWidth(200)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        info_label = QLabel("威胁情报列表 - 与服务器同步的恶意IP地址库")
        info_label.setStyleSheet("color: #888; font-size: 12px; padding: 2px 0;")
        layout.addWidget(info_label)

        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(10)
        self.blacklist_table.setHorizontalHeaderLabels([
            "IP", "端口", "威胁类型", "归属地", "标签", "关联病毒", "描述", "来源", "状态", "创建时间"
        ])
        self.blacklist_table.horizontalHeader().setStretchLastSection(True)
        self.blacklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.blacklist_table.setAlternatingRowColors(True)
        self.blacklist_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.blacklist_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.blacklist_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.blacklist_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.blacklist_table)

    def _on_search_changed(self):
        self._search_timer.start(300)

    def _do_filter(self):
        keyword = self.search_input.text().strip().lower()
        if not keyword:
            self.refresh_blacklist()
            return
        self._query_blacklist(keyword=keyword)

    def _query_blacklist(self, keyword="", threat_type="", status=""):
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("加载中...")

        filters = {
            "keyword": keyword,
            "threat_type": threat_type,
            "status": status,
        }
        self._blacklist_worker = BlacklistQueryWorker(self.malicious_mgr, filters)
        self._blacklist_worker.data_ready.connect(self._on_blacklist_result)
        self._blacklist_worker.start()

    def _on_blacklist_result(self, result):
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新列表")

        if isinstance(result, dict) and "error" in result:
            print(f"查询黑名单失败: {result['error']}")
            return

        ips = result
        self.blacklist_table.setUpdatesEnabled(False)
        self.blacklist_table.setRowCount(len(ips))
        for i, ip in enumerate(ips):
            self.blacklist_table.setItem(i, 0, QTableWidgetItem(ip["ip"]))
            self.blacklist_table.setItem(i, 1, QTableWidgetItem(str(ip["port"])))
            self.blacklist_table.setItem(i, 2, QTableWidgetItem(ip["threat_type"]))
            self.blacklist_table.setItem(i, 3, QTableWidgetItem(ip.get("location", "") or "-"))
            self.blacklist_table.setItem(i, 4, QTableWidgetItem(ip.get("tags", "") or "-"))
            self.blacklist_table.setItem(i, 5, QTableWidgetItem(ip.get("related_virus", "") or "-"))
            self.blacklist_table.setItem(i, 6, QTableWidgetItem(ip["description"]))
            self.blacklist_table.setItem(i, 7, QTableWidgetItem(ip["source"]))

            status = ip.get("status", "active")
            status_item = QTableWidgetItem("有效" if status == "active" else "已过期")
            if status == "expired":
                status_item.setForeground(QBrush(QColor("#ff9800")))
                status_item.setBackground(QColor(0x3a, 0x2a, 0x10))
            else:
                status_item.setForeground(QBrush(QColor("#4caf50")))
            self.blacklist_table.setItem(i, 8, status_item)

            self.blacklist_table.setItem(i, 9, QTableWidgetItem(ip.get("create_time", "")))
        self.blacklist_table.setUpdatesEnabled(True)

    def refresh_blacklist(self):
        keyword = self.search_input.text().strip().lower()
        if keyword:
            self._query_blacklist(keyword=keyword)
        else:
            self._query_blacklist()

    def add_black_ip(self):
        dialog = AddBlackIPDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if not data["ip"]:
                show_warning(self, "错误", "请输入IP地址")
                return
            success = self.malicious_mgr.add_black_ip(
                data["ip"], data["port"],
                data["threat_type"], data["description"],
                location=data.get("location", ""),
                tags=data.get("tags", ""),
                related_virus=data.get("related_virus", ""),
            )
            if success:
                show_info(self, "成功", f"已添加黑名单: {data['ip']}")
                self.refresh_blacklist()
            else:
                show_warning(self, "提示", f"IP {data['ip']} 已存在于黑名单中")

    def show_context_menu(self, pos):
        from PyQt6.QtGui import QAction
        menu = QMenu()

        expire_action = QAction("标记过期", self)
        expire_action.triggered.connect(self.expire_selected_ip)
        menu.addAction(expire_action)

        activate_action = QAction("标记有效", self)
        activate_action.triggered.connect(self.activate_selected_ip)
        menu.addAction(activate_action)

        menu.addSeparator()

        delete_action = QAction("删除", self)
        delete_action.triggered.connect(self.delete_selected_ip)
        menu.addAction(delete_action)

        copy_action = QAction("复制IP地址", self)
        copy_action.triggered.connect(self.copy_ip)
        menu.addAction(copy_action)

        menu.exec(self.blacklist_table.viewport().mapToGlobal(pos))

    def _get_selected_ip_id(self):
        rows = set()
        for item in self.blacklist_table.selectedItems():
            rows.add(item.row())
        if not rows:
            return None
        row = rows.pop()
        ips = self.malicious_mgr.get_all_black_ips()
        ip_text = self.blacklist_table.item(row, 0).text()
        port_text = int(self.blacklist_table.item(row, 1).text() or "0")
        for ip in ips:
            if ip["ip"] == ip_text and ip["port"] == port_text:
                return ip["id"]
        return None

    def delete_selected_ip(self):
        ip_id = self._get_selected_ip_id()
        if ip_id is None:
            return

        reply = show_question(
            self, "确认删除",
            f"确定要删除该恶意IP记录吗？"
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.malicious_mgr.delete_black_ip(ip_id)
            self.refresh_blacklist()

    def expire_selected_ip(self):
        ip_id = self._get_selected_ip_id()
        if ip_id is None:
            show_warning(self, "提示", "请先选中一条IP记录")
            return
        self.malicious_mgr.expire_black_ip(ip_id)
        self.refresh_blacklist()
        show_info(self, "成功", "已将该IP标记为过期，不再被视为恶意IP")

    def activate_selected_ip(self):
        ip_id = self._get_selected_ip_id()
        if ip_id is None:
            show_warning(self, "提示", "请先选中一条IP记录")
            return
        self.malicious_mgr.activate_black_ip(ip_id)
        self.refresh_blacklist()
        show_info(self, "成功", "已将该IP恢复为有效状态")

    def copy_ip(self):
        rows = set()
        for item in self.blacklist_table.selectedItems():
            rows.add(item.row())
        if rows:
            row = rows.pop()
            ip = self.blacklist_table.item(row, 0).text()
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(ip)

    def sync_with_server(self):
        config = self._load_sync_config()
        dialog = SyncConfigDialog(config, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        config = dialog.get_config()
        self._save_sync_config(config)

        server_url = config.get("server_url", "").strip()
        if not server_url:
            show_warning(self, "提示", "请先配置服务器地址")
            return

        self.sync_btn.setEnabled(False)
        self.sync_btn.setText("同步中...")

        import socket as sock_mod
        import platform
        client_id = config.get("client_id", "")
        if not client_id:
            client_id = get_machine_id()
        try:
            ver = platform.version()
            parts = ver.split(".")
            build = int(parts[-1]) if len(parts) >= 3 and parts[-1].isdigit() else 0
            if build >= 22000:
                os_name = "Windows 11"
            elif build >= 10240:
                os_name = "Windows 10"
            else:
                os_name = platform.system()
            
            edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
            edition_map = {
                "CoreCountrySpecific": "家庭中文版",
                "Core": "家庭版",
                "Professional": "专业版",
                "Enterprise": "企业版",
                "Education": "教育版",
                "ProfessionalEducation": "专业教育版",
                "ProfessionalWorkstation": "专业工作站版",
                "Server": "服务器版",
            }
            edition = edition_map.get(edition, edition)
            os_str = f"{os_name} {edition} (版本 {build})" if edition else f"{os_name} (版本 {build})"
        except Exception:
            os_str = f"{platform.system()} {platform.release()}"
        client_info = {
            "client_id": client_id,
            "hostname": sock_mod.gethostname(),
            "version": "1.0.0",
            "os": os_str,
        }

        secret_key = config.get("secret_key", "")
        sync_mode = config.get("sync_mode", "incremental")

        from PyQt6.QtCore import QThread, pyqtSignal

        class SyncThread(QThread):
            finished = pyqtSignal(dict)
            error = pyqtSignal(str)

            def __init__(self, malicious_mgr, server_url, secret_key, client_info, sync_mode):
                super().__init__()
                self.malicious_mgr = malicious_mgr
                self.server_url = server_url
                self.secret_key = secret_key
                self.client_info = client_info
                self.sync_mode = sync_mode

            def run(self):
                import threading
                result_container = []

                def target():
                    try:
                        if self.sync_mode == "full":
                            result = self.malicious_mgr.sync_full_from_server(self.server_url, self.secret_key, self.client_info)
                        elif self.sync_mode == "push":
                            result = self.malicious_mgr.push_to_server_only(self.server_url, self.secret_key, self.client_info)
                        else:
                            result = self.malicious_mgr.sync_from_server(self.server_url, self.secret_key, self.client_info)
                        result_container.append(result)
                    except Exception as e:
                        result_container.append({"error": str(e)})

                t = threading.Thread(target=target, daemon=True)
                t.start()
                t.join(timeout=30)

                if t.is_alive():
                    self.error.emit("情报同步超时，请检查网络连接后重试")
                else:
                    result = result_container[0]
                    if "error" in result:
                        self.error.emit(result["error"])
                    else:
                        self.finished.emit(result)

        def _show_error_box(title, text):
            show_critical(self, title, text)

        def on_sync_finished(result):
            self.sync_btn.setEnabled(True)
            self.sync_btn.setText("情报同步")
            if result["success"]:
                pushed = result.get("pushed", 0)
                updated = result.get("updated", 0)
                if pushed:
                    msg = f"数据推送完成！\n已推送: {pushed} 条IP\n推送到服务端的数据需要管理员审核"
                else:
                    msg = f"情报同步完成！\n新增恶意IP: {result['added']} 条\n服务器总数: {result['total']} 条"
                if updated:
                    msg += f"\n字段更新: {updated} 条"
                show_info(
                    self, "同步成功", msg
                )
                self.refresh_blacklist()
            else:
                show_critical(self, "同步失败", f"情报同步失败:\n{result['error']}")

        def on_sync_error(err_msg):
            self.sync_btn.setEnabled(True)
            self.sync_btn.setText("情报同步")
            show_critical(self, "同步失败", f"情报同步出错:\n{err_msg}")

        self.sync_thread = SyncThread(self.malicious_mgr, server_url, secret_key, client_info, sync_mode)
        self.sync_thread.finished.connect(on_sync_finished)
        self.sync_thread.error.connect(on_sync_error)
        self.sync_thread.start()

    def _load_sync_config(self):
        config_file = os.path.join(get_data_dir(), "sync_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            "server_url": "http://127.0.0.1:18080",
            "secret_key": "",
            "sync_mode": "incremental",
            "client_id": "",
        }

    def _save_sync_config(self, config):
        config_file = os.path.join(get_data_dir(), "sync_config.json")
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except IOError:
            pass

    def on_activate(self):
        if not self._activated:
            self._activated = True
            self.refresh_blacklist()
