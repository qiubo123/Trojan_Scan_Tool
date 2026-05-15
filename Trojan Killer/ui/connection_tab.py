import psutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QHeaderView, QGroupBox,
    QMessageBox, QFileDialog, QDialog, QTextEdit, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont

from core.connection_logger import ConnectionLogger
from .msg_box import show_warning, show_info, show_critical, show_question


class DetailFetchWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, pid):
        super().__init__()
        self.pid = pid

    def run(self):
        try:
            proc = psutil.Process(self.pid)
            detail = {
                "pid": self.pid,
                "name": proc.name(),
                "exe": "",
                "cwd": "",
                "cmdline": "",
                "username": "",
                "status": proc.status(),
                "create_time": "",
                "num_threads": proc.num_threads(),
                "cpu_percent": proc.cpu_percent(interval=0),
                "memory_mb": proc.memory_info().rss / 1024 / 1024,
                "connections": [],
                "open_files": [],
            }
            try:
                detail["exe"] = proc.exe()
            except Exception:
                detail["exe"] = "N/A"
            try:
                detail["cwd"] = proc.cwd()
            except Exception:
                detail["cwd"] = "N/A"
            try:
                detail["cmdline"] = " ".join(proc.cmdline())
            except Exception:
                detail["cmdline"] = "N/A"
            try:
                detail["username"] = proc.username()
            except Exception:
                detail["username"] = "N/A"
            try:
                from datetime import datetime
                detail["create_time"] = datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                detail["create_time"] = "N/A"
            try:
                for i, conn in enumerate(proc.connections(kind="inet")):
                    if i >= 30:
                        break
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    detail["connections"].append({"local": laddr, "remote": raddr, "status": conn.status})
            except Exception:
                pass
            try:
                for f in proc.open_files()[:30]:
                    detail["open_files"].append(f.path)
            except Exception:
                pass
            self.data_ready.emit(detail)
        except psutil.NoSuchProcess:
            self.data_ready.emit({"pid": self.pid, "error": "进程已结束"})
        except psutil.AccessDenied:
            self.data_ready.emit({"pid": self.pid, "error": "权限不足"})
        except Exception as e:
            self.data_ready.emit({"pid": self.pid, "error": str(e)})


class ProcessDetailDialog(QDialog):
    def __init__(self, log_entry, parent=None):
        super().__init__(parent)
        self.setWindowTitle("进程详情 - %s" % log_entry.get("process_name", ""))
        self.setMinimumSize(640, 520)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel("<b style='font-size:16px;color:#e94560;'>进程详情</b>")
        layout.addWidget(title)

        self.detail_box = QGroupBox("外联日志记录信息")
        box_layout = QVBoxLayout(self.detail_box)
        self.log_info_text = QTextEdit()
        self.log_info_text.setReadOnly(True)
        self.log_info_text.setMaximumHeight(160)
        box_layout.addWidget(self.log_info_text)
        layout.addWidget(self.detail_box)

        self.live_box = QGroupBox("当前实时进程信息")
        live_layout = QVBoxLayout(self.live_box)
        self.live_text = QTextEdit()
        self.live_text.setReadOnly(True)
        live_layout.addWidget(self.live_text)
        layout.addWidget(self.live_box)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        self._populate_log_info(log_entry)

        self.live_text.setText("正在获取当前进程信息...")
        self._worker = DetailFetchWorker(log_entry.get("pid", 0))
        self._worker.data_ready.connect(self._on_detail)
        self._worker.start()

    def _populate_log_info(self, log):
        text = f"""PID: {log.get('pid', 'N/A')}
进程名: {log.get('process_name', 'N/A')}
进程路径: {log.get('process_path', 'N/A')}
命令行: {log.get('process_cmdline', 'N/A')}
工作目录: {log.get('process_cwd', 'N/A')}
进程创建时间: {log.get('process_create_time', 'N/A')}
用户名: {log.get('username', 'N/A')}

连接时间: {log.get('log_time', 'N/A')}
远程地址: {log.get('remote_ip', '')}:{log.get('remote_port', '')}
本地地址: {log.get('local_ip', '')}:{log.get('local_port', '')}
协议: {log.get('protocol', 'N/A')}    状态: {log.get('status', 'N/A')}
恶意: {'是' if log.get('is_malicious') else '否'}
"""
        self.log_info_text.setText(text)

    def _on_detail(self, detail):
        if "error" in detail:
            self.live_text.setText("进程已结束或无法访问: %s" % detail["error"])
            return

        text = f"""PID: {detail.get('pid', 'N/A')}
名称: {detail.get('name', 'N/A')}
路径: {detail.get('exe', 'N/A')}
命令行: {detail.get('cmdline', 'N/A')}
工作目录: {detail.get('cwd', 'N/A')}
用户名: {detail.get('username', 'N/A')}
状态: {detail.get('status', 'N/A')}
创建时间: {detail.get('create_time', 'N/A')}
线程数: {detail.get('num_threads', 'N/A')}
CPU使用率: {detail.get('cpu_percent', 'N/A')}%
内存使用: {detail.get('memory_mb', 'N/A'):.1f} MB

网络连接 ({len(detail.get('connections', []))} 个):
"""
        for conn in detail.get("connections", []):
            text += "  %s -> %s [%s]\n" % (conn["local"], conn["remote"], conn["status"])

        text += "\n打开的文件 (%d 个):\n" % len(detail.get("open_files", []))
        for f in detail.get("open_files", []):
            text += "  %s\n" % f

        self.live_text.setText(text)


class CaptureWorker(QThread):
    finished = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, logger):
        super().__init__()
        self.logger = logger

    def run(self):
        try:
            count = self.logger.capture_snapshot()
            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))


class LogQueryWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, logger, page, page_size, filters):
        super().__init__()
        self.logger = logger
        self.page = page
        self.page_size = page_size
        self.filters = filters

    def run(self):
        try:
            result = self.logger.get_logs(self.page, self.page_size, self.filters)
            self.data_ready.emit(result)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ScanMaliciousWorker(QThread):
    finished = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, logger):
        super().__init__()
        self.logger = logger

    def run(self):
        try:
            count = self.logger.scan_malicious_connections()
            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))


class ConnectionTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.logger = ConnectionLogger()

        self.current_page = 1
        self.total_pages = 1
        self.page_size = 100
        self._activated = False
        self._refresh_in_progress = False
        self._current_logs = []

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._do_search)

        self._refresh_timeout_timer = QTimer(self)
        self._refresh_timeout_timer.setSingleShot(True)
        self._refresh_timeout_timer.timeout.connect(self._on_refresh_timeout)

        self._cached_malicious_brush = QBrush(QColor("#ff6b35"))
        self._cached_malicious_font = QFont("Microsoft YaHei", 10, QFont.Weight.Bold)
        self._cached_malicious_bg = QColor(0x3d, 0x1a, 0x0a)
        self._cached_safe_brush = QBrush(QColor("#27ae60"))

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.capture_btn = QPushButton("捕获快照")
        self.capture_btn.setObjectName("dangerBtn")
        self.capture_btn.clicked.connect(self.capture_snapshot)
        toolbar.addWidget(self.capture_btn)

        self.scan_btn = QPushButton("扫描恶意连接")
        self.scan_btn.setObjectName("warningBtn")
        self.scan_btn.clicked.connect(self.scan_malicious)
        toolbar.addWidget(self.scan_btn)

        self.refresh_btn = QPushButton("刷新日志")
        self.refresh_btn.clicked.connect(self.refresh_logs)
        toolbar.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("导出CSV")
        self.export_btn.clicked.connect(self.export_logs)
        toolbar.addWidget(self.export_btn)

        self.clear_btn = QPushButton("清空日志")
        self.clear_btn.setObjectName("warningBtn")
        self.clear_btn.clicked.connect(self.clear_logs)
        toolbar.addWidget(self.clear_btn)

        self.detail_btn = QPushButton("查看进程详情")
        self.detail_btn.clicked.connect(self.show_selected_detail)
        toolbar.addWidget(self.detail_btn)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索IP或进程名...")
        self.search_input.setMinimumWidth(200)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)

        self.malicious_only_cb = QCheckBox("仅恶意")
        self.malicious_only_cb.stateChanged.connect(self.refresh_logs)
        toolbar.addWidget(self.malicious_only_cb)

        toolbar.addStretch()

        self.page_label = QLabel("第 1 页 / 共 1 页")
        toolbar.addWidget(self.page_label)

        self.prev_btn = QPushButton("上一页")
        self.prev_btn.clicked.connect(self.prev_page)
        toolbar.addWidget(self.prev_btn)

        self.next_btn = QPushButton("下一页")
        self.next_btn.clicked.connect(self.next_page)
        toolbar.addWidget(self.next_btn)

        layout.addLayout(toolbar)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(11)
        self.log_table.setHorizontalHeaderLabels([
            "时间", "本地IP", "本地端口", "远程IP", "远程端口",
            "协议", "状态", "PID", "进程名", "用户名", "恶意"
        ])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.log_table.setColumnWidth(0, 160)
        self.log_table.setColumnWidth(1, 120)
        self.log_table.setColumnWidth(2, 80)
        self.log_table.setColumnWidth(3, 130)
        self.log_table.setColumnWidth(4, 80)
        self.log_table.setColumnWidth(5, 60)
        self.log_table.setColumnWidth(6, 60)
        self.log_table.setColumnWidth(7, 60)
        self.log_table.setColumnWidth(8, 120)
        self.log_table.setColumnWidth(9, 100)
        self.log_table.setColumnWidth(10, 50)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.log_table.itemDoubleClicked.connect(self.show_selected_detail)
        layout.addWidget(self.log_table)

    def _get_selected_log(self):
        rows = set()
        for item in self.log_table.selectedItems():
            rows.add(item.row())
        if rows:
            row = rows.pop()
            if row < len(self._current_logs):
                return self._current_logs[row]
        return None

    def show_selected_detail(self, item=None):
        log = self._get_selected_log()
        if not log:
            show_warning(self, "提示", "请先选中一条日志记录")
            return
        dialog = ProcessDetailDialog(log, self)
        dialog.exec()

    def capture_snapshot(self):
        self.capture_btn.setEnabled(False)
        self.capture_btn.setText("捕获中...")

        def on_finished(count):
            self.capture_btn.setEnabled(True)
            self.capture_btn.setText("捕获快照")
            show_info(self, "捕获完成", f"已记录 {count} 条外联连接")
            self.refresh_logs()

        def on_error(msg):
            self.capture_btn.setEnabled(True)
            self.capture_btn.setText("捕获快照")
            show_critical(self, "捕获失败", f"捕获连接快照失败: {msg}")

        self.capture_worker = CaptureWorker(self.logger)
        self.capture_worker.finished.connect(on_finished)
        self.capture_worker.error.connect(on_error)
        self.capture_worker.start()

    def scan_malicious(self):
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("扫描中...")

        def on_finished(count):
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("扫描恶意连接")
            if count > 0:
                show_warning(self, "扫描完成", f"发现 {count} 条恶意连接，已标记并置顶显示")
            else:
                show_info(self, "扫描完成", "未发现新的恶意连接")
            self.current_page = 1
            self.refresh_logs()

        def on_error(msg):
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("扫描恶意连接")
            show_critical(self, "扫描失败", f"扫描恶意连接失败: {msg}")

        self.scan_worker = ScanMaliciousWorker(self.logger)
        self.scan_worker.finished.connect(on_finished)
        self.scan_worker.error.connect(on_error)
        self.scan_worker.start()

    def _on_search_changed(self):
        self._search_timer.start(300)

    def _do_search(self):
        self.current_page = 1
        self.refresh_logs()

    def refresh_logs(self):
        if self._refresh_in_progress:
            if self._query_worker and not self._query_worker.isRunning():
                self._reset_refresh_state()
            else:
                return
        self._refresh_in_progress = True
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("加载中...")

        filters = {}
        keyword = self.search_input.text().strip()
        if keyword:
            filters["keyword"] = keyword
        if self.malicious_only_cb.isChecked():
            filters["malicious_only"] = True

        self._query_worker = LogQueryWorker(self.logger, self.current_page, self.page_size, filters)
        self._query_worker.data_ready.connect(self._on_query_result)
        self._query_worker.start()
        self._refresh_timeout_timer.start(30000)

    def _on_query_result(self, result):
        self._refresh_timeout_timer.stop()
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新日志")

        if isinstance(result, dict) and "error" in result:
            print(f"刷新日志失败: {result['error']}")
            return

        self.total_pages = result["total_pages"]
        self.page_label.setText(f"第 {result['page']} 页 / 共 {result['total_pages']} 页 (共 {result['total']} 条)")

        self.prev_btn.setEnabled(self.current_page > 1)
        self.next_btn.setEnabled(self.current_page < self.total_pages)

        logs = result["data"]
        sorted_logs = sorted(logs, key=lambda x: (0 if x["is_malicious"] else 1, x["log_time"]), reverse=True)
        self._current_logs = sorted_logs
        self.log_table.setUpdatesEnabled(False)
        self.log_table.setRowCount(len(sorted_logs))

        for i, log in enumerate(sorted_logs):
            self.log_table.setItem(i, 0, QTableWidgetItem(log["log_time"]))
            self.log_table.setItem(i, 1, QTableWidgetItem(log["local_ip"]))
            self.log_table.setItem(i, 2, QTableWidgetItem(str(log["local_port"])))
            self.log_table.setItem(i, 3, QTableWidgetItem(log["remote_ip"]))
            self.log_table.setItem(i, 4, QTableWidgetItem(str(log["remote_port"])))
            self.log_table.setItem(i, 5, QTableWidgetItem(log["protocol"]))
            self.log_table.setItem(i, 6, QTableWidgetItem(log["status"]))
            self.log_table.setItem(i, 7, QTableWidgetItem(str(log["pid"])))
            self.log_table.setItem(i, 8, QTableWidgetItem(log["process_name"]))
            self.log_table.setItem(i, 9, QTableWidgetItem(log["username"]))

            is_malicious = log["is_malicious"]
            malicious_item = QTableWidgetItem("是" if is_malicious else "否")
            if is_malicious:
                malicious_item.setForeground(self._cached_malicious_brush)
                malicious_item.setFont(self._cached_malicious_font)
                for col in range(11):
                    item = self.log_table.item(i, col)
                    if item:
                        item.setBackground(self._cached_malicious_bg)
            else:
                malicious_item.setForeground(self._cached_safe_brush)
            self.log_table.setItem(i, 10, malicious_item)

        self.log_table.setUpdatesEnabled(True)

    def _reset_refresh_state(self):
        self._refresh_timeout_timer.stop()
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新日志")

    def _on_refresh_timeout(self):
        if self._refresh_in_progress:
            print("刷新日志超时，已重置状态")
            if self._query_worker and self._query_worker.isRunning():
                self._query_worker.quit()
                self._query_worker.wait(2000)
            self._reset_refresh_state()

    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.refresh_logs()

    def next_page(self):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.refresh_logs()

    def export_logs(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "connection_logs.csv",
            "CSV文件 (*.csv)"
        )
        if filepath:
            try:
                count = self.logger.export_logs(filepath, self.malicious_only_cb.isChecked())
                from ui.report_tab import _show_success_box
                _show_success_box("导出成功", f"已导出 {count} 条日志到:\n{filepath}", self)
            except Exception as e:
                show_critical(self, "导出失败", f"导出日志失败: {e}")

    def clear_logs(self):
        reply = show_question(self, "确认清空",
            "确定要清空所有连接日志吗？\n此操作不可恢复！")
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.logger.db.delete("connection_log", "1=1", allow_all=True)
                self.refresh_logs()
                show_info(self, "成功", "日志已清空")
            except Exception as e:
                show_critical(self, "失败", f"清空日志失败: {e}")

    def on_activate(self):
        if not self._activated:
            self._activated = True
        self.refresh_logs()
