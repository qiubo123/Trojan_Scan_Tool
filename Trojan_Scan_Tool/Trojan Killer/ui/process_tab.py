from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QHeaderView, QGroupBox,
    QMessageBox, QMenu, QSplitter, QTextEdit, QComboBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush, QAction
from PyQt6.QtWidgets import QApplication

from core.process_monitor import ProcessMonitor
from .msg_box import show_info, show_warning, show_question


class ProcessWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, monitor, db):
        super().__init__()
        self.monitor = monitor
        self.db = db

    def run(self):
        try:
            data = self.monitor.get_all_processes_light()
            if self.db:
                self.db.delete("threat_found", "threat_type='可疑进程'")
                threats = []
                for p in data:
                    if p.is_suspicious:
                        threats.append({
                            "scan_id": 0,
                            "threat_type": "可疑进程",
                            "threat_name": p.name,
                            "threat_path": p.exe,
                            "risk_level": "中危",
                            "process_name": p.name,
                            "process_pid": p.pid,
                            "description": p.suspicious_reasons,
                            "suggestion": "建议结束该进程并进行安全检查",
                        })
                if threats:
                    try:
                        self.db.insert_batch("threat_found", threats)
                    except Exception:
                        pass
            self.data_ready.emit(data)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ProcessDetailWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, monitor, pid):
        super().__init__()
        self.monitor = monitor
        self.pid = pid

    def run(self):
        try:
            data = self.monitor.get_process_detail(self.pid)
            self.data_ready.emit(data)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class ProcessTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.monitor = ProcessMonitor()

        self.all_processes = []
        self.worker = None
        self._activated = False

        self.init_ui()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_processes)
        self.refresh_timer.setInterval(10000)
        self._refresh_in_progress = False

        self._refresh_timeout_timer = QTimer(self)
        self._refresh_timeout_timer.setSingleShot(True)
        self._refresh_timeout_timer.timeout.connect(self._on_refresh_timeout)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self.filter_processes)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索进程名或PID...")
        self.search_input.setMinimumWidth(250)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)

        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        toolbar.addWidget(self.refresh_btn)

        self.kill_btn = QPushButton("结束进程")
        self.kill_btn.setObjectName("dangerBtn")
        self.kill_btn.clicked.connect(self.kill_selected_process)
        toolbar.addWidget(self.kill_btn)

        self.force_kill_btn = QPushButton("强制结束")
        self.force_kill_btn.setObjectName("dangerBtn")
        self.force_kill_btn.clicked.connect(self.force_kill_selected_process)
        toolbar.addWidget(self.force_kill_btn)

        self.show_suspicious_only_btn = QPushButton("仅显示可疑")
        self.show_suspicious_only_btn.setObjectName("warningBtn")
        self.show_suspicious_only_btn.setCheckable(True)
        self.show_suspicious_only_btn.clicked.connect(self.toggle_suspicious_filter)
        toolbar.addWidget(self.show_suspicious_only_btn)

        toolbar.addStretch()

        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(8)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "进程名", "CPU%", "内存(MB)", "用户名", "线程数", "可疑", "原因"
        ])
        self.process_table.horizontalHeader().setStretchLastSection(True)
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.process_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.process_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.process_table.setSortingEnabled(True)
        self.process_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.show_context_menu)
        self.process_table.itemDoubleClicked.connect(self.show_process_detail)
        self.process_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.process_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        splitter.addWidget(self.process_table)

        self.detail_group = QGroupBox("进程详情")
        self.detail_group.setVisible(False)
        detail_layout = QVBoxLayout(self.detail_group)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        detail_layout.addWidget(self.detail_text)
        splitter.addWidget(self.detail_group)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def refresh_processes(self):
        if self._refresh_in_progress:
            if self.worker and not self.worker.isRunning():
                self._reset_refresh_state()
            else:
                return
        self._refresh_in_progress = True
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("加载中...")

        self.worker = ProcessWorker(self.monitor, self.main_window.db)
        self.worker.data_ready.connect(self._on_process_data)
        self.worker.start()

        self._refresh_timeout_timer.start(30000)

    def _on_process_data(self, data):
        self._refresh_timeout_timer.stop()
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新")
        if isinstance(data, dict) and "error" in data:
            print(f"刷新进程列表失败: {data['error']}")
            self.refresh_btn.setText("刷新（点击重试）")
            return
        self.all_processes = data
        if not self.refresh_timer.isActive():
            self.refresh_timer.start()
        keyword = self.search_input.text().strip().lower()
        if keyword:
            self.filter_processes()
        else:
            self.display_processes(data)

    def display_processes(self, processes):
        sorted_processes = sorted(processes, key=lambda x: (0 if x.is_suspicious else 1, x.name.lower()))
        
        self.process_table.setSortingEnabled(False)
        self.process_table.setRowCount(len(sorted_processes))

        for i, p in enumerate(sorted_processes):
            pid_item = QTableWidgetItem(str(p.pid))
            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.process_table.setItem(i, 0, pid_item)

            name_item = QTableWidgetItem(p.name)
            self.process_table.setItem(i, 1, name_item)

            cpu_item = QTableWidgetItem(str(p.cpu_percent))
            cpu_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if p.cpu_percent > 50:
                cpu_item.setForeground(QBrush(QColor("#e94560")))
            elif p.cpu_percent > 30:
                cpu_item.setForeground(QBrush(QColor("#f39c12")))
            self.process_table.setItem(i, 2, cpu_item)

            mem_item = QTableWidgetItem(f"{p.memory_mb:.1f}")
            mem_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if p.memory_mb > 500:
                mem_item.setForeground(QBrush(QColor("#e94560")))
            self.process_table.setItem(i, 3, mem_item)

            self.process_table.setItem(i, 4, QTableWidgetItem(p.username))
            self.process_table.setItem(i, 5, QTableWidgetItem(str(p.num_threads)))

            suspicious_item = QTableWidgetItem("是" if p.is_suspicious else "否")
            if p.is_suspicious:
                suspicious_item.setForeground(QBrush(QColor("#e94560")))
                suspicious_item.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.Bold))
            else:
                suspicious_item.setForeground(QBrush(QColor("#27ae60")))
            self.process_table.setItem(i, 6, suspicious_item)

            self.process_table.setItem(i, 7, QTableWidgetItem(p.suspicious_reasons))

            if p.is_suspicious:
                pid_item.setBackground(QColor(0x3a, 0x15, 0x20))
                name_item.setBackground(QColor(0x3a, 0x15, 0x20))
                cpu_item.setBackground(QColor(0x3a, 0x15, 0x20))
                mem_item.setBackground(QColor(0x3a, 0x15, 0x20))

        self.process_table.setSortingEnabled(True)

    def _on_search_changed(self):
        self._search_timer.start(300)

    def filter_processes(self):
        keyword = self.search_input.text().strip().lower()
        if not keyword:
            self.display_processes(self.all_processes)
            return

        filtered = [
            p for p in self.all_processes
            if keyword in p.name.lower() or keyword in str(p.pid)
        ]
        self.display_processes(filtered)

    def toggle_suspicious_filter(self):
        if self.show_suspicious_only_btn.isChecked():
            suspicious = [p for p in self.all_processes if p.is_suspicious]
            self.display_processes(suspicious)
            self.show_suspicious_only_btn.setText("显示全部")
        else:
            self.display_processes(self.all_processes)
            self.show_suspicious_only_btn.setText("仅显示可疑")

    def kill_selected_process(self):
        rows = set()
        for item in self.process_table.selectedItems():
            rows.add(item.row())

        if not rows:
            show_info(self, "提示", "请先选择要结束的进程")
            return

        if len(rows) > 1:
            reply = show_question(self, "确认结束",
                f"确定要结束选中的 {len(rows)} 个进程吗？")
            if reply != QMessageBox.StandardButton.Yes:
                return

        for row in rows:
            pid = int(self.process_table.item(row, 0).text())
            success, msg = self.monitor.kill_process(pid, force=False)
            if not success:
                show_warning(self, "结束失败", f"PID {pid}: {msg}")

        self.refresh_processes()

    def force_kill_selected_process(self):
        rows = set()
        for item in self.process_table.selectedItems():
            rows.add(item.row())

        if not rows:
            show_info(self, "提示", "请先选择要强制结束的进程")
            return

        reply = show_question(self, "确认强制结束",
            f"确定要强制结束选中的 {len(rows)} 个进程吗？\n强制结束可能导致数据丢失！")
        if reply != QMessageBox.StandardButton.Yes:
            return

        for row in rows:
            pid = int(self.process_table.item(row, 0).text())
            success, msg = self.monitor.kill_process(pid, force=True)
            if not success:
                show_warning(self, "结束失败", f"PID {pid}: {msg}")

        self.refresh_processes()

    def show_context_menu(self, pos):
        menu = QMenu()
        detail_action = QAction("查看详情", self)
        detail_action.triggered.connect(self.show_detail_for_selected)
        menu.addAction(detail_action)

        menu.addSeparator()

        kill_action = QAction("结束进程", self)
        kill_action.triggered.connect(self.kill_selected_process)
        menu.addAction(kill_action)

        force_kill_action = QAction("强制结束", self)
        force_kill_action.triggered.connect(self.force_kill_selected_process)
        menu.addAction(force_kill_action)

        menu.addSeparator()

        copy_action = QAction("复制PID", self)
        copy_action.triggered.connect(self.copy_pid)
        menu.addAction(copy_action)

        menu.exec(self.process_table.viewport().mapToGlobal(pos))

    def show_detail_for_selected(self):
        rows = set()
        for item in self.process_table.selectedItems():
            rows.add(item.row())
        if rows:
            row = rows.pop()
            pid = int(self.process_table.item(row, 0).text())
            self.show_process_detail_by_pid(pid)

    def show_process_detail(self, item):
        row = item.row()
        pid = int(self.process_table.item(row, 0).text())
        self.show_process_detail_by_pid(pid)

    def show_process_detail_by_pid(self, pid):
        self.detail_group.setVisible(True)
        self.detail_text.setText(f"正在获取进程 {pid} 的详情...")
        
        self.detail_worker = ProcessDetailWorker(self.monitor, pid)
        self.detail_worker.data_ready.connect(self._on_process_detail)
        self.detail_worker.start()

    def _on_process_detail(self, detail):
        if "error" in detail:
            self.detail_text.setText(f"无法获取进程详情: {detail['error']}")
            return

        text = f"""【进程基本信息】
PID: {detail.get('pid', 'N/A')}
名称: {detail.get('name', 'N/A')}
路径: {detail.get('exe', 'N/A')}
工作目录: {detail.get('cwd', 'N/A')}
用户名: {detail.get('username', 'N/A')}
状态: {detail.get('status', 'N/A')}
创建时间: {detail.get('create_time', 'N/A')}
线程数: {detail.get('num_threads', 'N/A')}
CPU使用率: {detail.get('cpu_percent', 'N/A')}%
内存使用: {detail.get('memory_mb', 'N/A')} MB

【网络连接 ({len(detail.get('connections', []))} 个)】
"""
        for conn in detail.get('connections', []):
            text += f"  {conn['local']} -> {conn['remote']} [{conn['status']}]\n"

        text += f"\n【打开的文件 ({len(detail.get('open_files', []))} 个)】\n"
        for f in detail.get('open_files', []):
            text += f"  {f}\n"

        self.detail_text.setText(text)

    def _reset_refresh_state(self):
        self._refresh_timeout_timer.stop()
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("刷新")

    def _on_refresh_timeout(self):
        if self._refresh_in_progress:
            print("刷新进程超时，已重置状态")
            if self.worker and self.worker.isRunning():
                self.worker.quit()
                self.worker.wait(2000)
            self._reset_refresh_state()

    def copy_pid(self):
        rows = set()
        for item in self.process_table.selectedItems():
            rows.add(item.row())
        if rows:
            row = rows.pop()
            pid = self.process_table.item(row, 0).text()
            clipboard = QApplication.clipboard()
            clipboard.setText(pid)

    def on_activate(self):
        if not self._activated:
            self._activated = True
        if not self.all_processes:
            self.refresh_processes()
