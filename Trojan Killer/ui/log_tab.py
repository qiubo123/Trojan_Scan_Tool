from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QHeaderView, QGroupBox,
    QMessageBox, QFileDialog, QComboBox, QCheckBox, QSpinBox,
    QApplication, QTextEdit, QDialog, QTabWidget, QDateTimeEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont

from core.log_collector import LogCollector
from .msg_box import show_info, show_critical


class LogCollectWorker(QThread):
    data_ready = pyqtSignal(object)

    def __init__(self, collector, start_time, end_time):
        super().__init__()
        self.collector = collector
        self.start_time = start_time
        self.end_time = end_time

    def run(self):
        try:
            logs = self.collector.collect_all(start_time=self.start_time, end_time=self.end_time)
            self.data_ready.emit(logs)
        except Exception as e:
            self.data_ready.emit({"error": str(e)})


class LogDetailDialog(QDialog):
    def __init__(self, log_entry, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"日志详情 - {log_entry.log_type}")
        self.setMinimumSize(600, 400)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            }
            QTextEdit {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
            QLabel {
                color: #a0a0c0;
                font-size: 13px;
                font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel(f"类型: {log_entry.log_type}"))
        info_layout.addWidget(QLabel(f"时间: {log_entry.time_str}"))
        info_layout.addWidget(QLabel(f"来源: {log_entry.source}"))
        info_layout.addWidget(QLabel(f"事件ID: {log_entry.event_id}"))
        info_layout.addWidget(QLabel(f"级别: {log_entry.level}"))
        info_layout.addStretch()
        layout.addLayout(info_layout)

        detail_text = QTextEdit()
        detail_text.setReadOnly(True)
        content = f"消息: {log_entry.message}\n\n"
        if log_entry.detail:
            content += "详细信息:\n"
            for key, value in log_entry.detail.items():
                if isinstance(value, list):
                    content += f"  {key}: {', '.join(str(v)[:100] for v in value[:10])}\n"
                elif isinstance(value, dict):
                    content += f"  {key}: {json.dumps(value, ensure_ascii=False)[:200]}\n"
                else:
                    content += f"  {key}: {str(value)[:200]}\n"
        detail_text.setPlainText(content)
        layout.addWidget(detail_text)

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        close_btn.setObjectName("primaryBtn")
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

import json


class LogTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.collector = LogCollector()
        self.all_logs = []
        self.filtered_logs = []
        self.current_page = 1
        self.total_pages = 1
        self.page_size = 100
        self._activated = False
        self._worker = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.collect_btn = QPushButton("收集日志")
        self.collect_btn.setObjectName("dangerBtn")
        self.collect_btn.clicked.connect(self.collect_logs)
        toolbar.addWidget(self.collect_btn)

        self.export_btn = QPushButton("导出CSV")
        self.export_btn.clicked.connect(self.export_logs)
        toolbar.addWidget(self.export_btn)

        self.filter_type = QComboBox()
        self.filter_type.addItems(["全部", "系统登录日志", "计划任务日志", "PowerShell运行日志", "防火墙外联日志", "浏览器下载与访问日志"])
        self.filter_type.currentTextChanged.connect(self.apply_filter)
        toolbar.addWidget(QLabel("类型:"))
        toolbar.addWidget(self.filter_type)

        self.filter_level = QComboBox()
        self.filter_level.addItems(["全部级别", "信息", "警告", "错误", "严重"])
        self.filter_level.currentTextChanged.connect(self.apply_filter)
        toolbar.addWidget(QLabel("级别:"))
        toolbar.addWidget(self.filter_level)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索关键词...")
        self.search_input.setMinimumWidth(150)
        self.search_input.textChanged.connect(self.apply_filter)
        toolbar.addWidget(self.search_input)

        from datetime import datetime, timedelta
        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setDateTime(datetime.now() - timedelta(hours=24))
        self.start_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.start_datetime.setCalendarPopup(True)

        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setDateTime(datetime.now())
        self.end_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_datetime.setCalendarPopup(True)

        toolbar.addWidget(QLabel("时间范围:"))
        toolbar.addWidget(self.start_datetime)
        toolbar.addWidget(QLabel("至"))
        toolbar.addWidget(self.end_datetime)

        toolbar.addStretch()

        self.page_label = QLabel("第 0 页 / 共 0 页 (共 0 条)")
        toolbar.addWidget(self.page_label)

        self.prev_btn = QPushButton("上一页")
        self.prev_btn.clicked.connect(self.prev_page)
        toolbar.addWidget(self.prev_btn)

        self.next_btn = QPushButton("下一页")
        self.next_btn.clicked.connect(self.next_page)
        toolbar.addWidget(self.next_btn)

        layout.addLayout(toolbar)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(7)
        self.log_table.setHorizontalHeaderLabels([
            "时间", "类型", "来源", "事件ID", "级别", "消息", "详情"
        ])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setStyleSheet("""
            QTableWidget::verticalHeader::section { background: transparent; }
        """)
        self.log_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.log_table.cellDoubleClicked.connect(self.show_detail)
        layout.addWidget(self.log_table)

        self.status_label = QLabel("就绪 - 点击「收集日志」获取系统日志")
        self.status_label.setStyleSheet("color: #a0a0c0; padding: 4px;")
        layout.addWidget(self.status_label)

    def collect_logs(self):
        if self._worker and self._worker.isRunning():
            return
        start_time = self.start_datetime.dateTime().toString("yyyy-MM-dd HH:mm:ss")
        end_time = self.end_datetime.dateTime().toString("yyyy-MM-dd HH:mm:ss")
        self.collect_btn.setEnabled(False)
        self.collect_btn.setText("收集中...")
        self.status_label.setText(f"正在收集 {start_time} 至 {end_time} 的日志...")
        self.log_table.setRowCount(0)
        QApplication.processEvents()

        self._worker = LogCollectWorker(self.collector, start_time, end_time)
        self._worker.data_ready.connect(self._on_collect_done)
        self._worker.start()

    def _on_collect_done(self, data):
        self.collect_btn.setEnabled(True)
        self.collect_btn.setText("收集日志")
        if isinstance(data, dict) and "error" in data:
            self.status_label.setText(f"收集失败: {data['error']}")
            show_critical(self, "收集失败", f"日志收集出错: {data['error']}")
            return

        self.all_logs = data
        self.status_label.setText(f"收集完成，共 {len(self.all_logs)} 条日志")
        self.apply_filter()

    def apply_filter(self):
        log_type = self.filter_type.currentText()
        level = self.filter_level.currentText()
        keyword = self.search_input.text().strip().lower()

        self.filtered_logs = []
        for log in self.all_logs:
            if log_type != "全部" and log.log_type != log_type:
                continue
            if level != "全部级别" and log.level != level:
                continue
            if keyword:
                if keyword not in log.message.lower() and keyword not in log.log_type.lower() and keyword not in log.source.lower():
                    continue
            self.filtered_logs.append(log)

        self.current_page = 1
        self.display_page()

    def display_page(self):
        total = len(self.filtered_logs)
        self.total_pages = max(1, (total + self.page_size - 1) // self.page_size)
        if self.current_page > self.total_pages:
            self.current_page = self.total_pages

        self.page_label.setText(f"第 {self.current_page} 页 / 共 {self.total_pages} 页 (共 {total} 条)")
        self.prev_btn.setEnabled(self.current_page > 1)
        self.next_btn.setEnabled(self.current_page < self.total_pages)

        start = (self.current_page - 1) * self.page_size
        end = min(start + self.page_size, total)
        page_logs = self.filtered_logs[start:end]

        self.log_table.setRowCount(len(page_logs))
        for i, log in enumerate(page_logs):
            self.log_table.setItem(i, 0, QTableWidgetItem(log.time_str))
            self.log_table.setItem(i, 1, QTableWidgetItem(log.log_type))
            self.log_table.setItem(i, 2, QTableWidgetItem(log.source))
            self.log_table.setItem(i, 3, QTableWidgetItem(str(log.event_id)))
            self.log_table.setItem(i, 4, QTableWidgetItem(log.level))
            self.log_table.setItem(i, 5, QTableWidgetItem(log.message[:200] if log.message else ""))

            detail_btn = QPushButton("查看")
            detail_btn.setStyleSheet("""
                QPushButton {
                    background-color: #0f3460;
                    color: #e0e0e0;
                    border: none;
                    border-radius: 3px;
                    padding: 2px 8px;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #1a5276;
                }
            """)
            detail_btn.clicked.connect(lambda checked, le=log: self.show_detail_for(le))
            self.log_table.setCellWidget(i, 6, detail_btn)

            level_item = self.log_table.item(i, 4)
            if level_item:
                if log.level == "错误" or log.level == "严重":
                    level_item.setForeground(QBrush(QColor("#e94560")))
                    level_item.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Bold))
                elif log.level == "警告":
                    level_item.setForeground(QBrush(QColor("#f39c12")))

    def show_detail_for(self, log_entry):
        dialog = LogDetailDialog(log_entry, self)
        dialog.exec()

    def show_detail(self, row, col):
        start = (self.current_page - 1) * self.page_size
        idx = start + row
        if 0 <= idx < len(self.filtered_logs):
            self.show_detail_for(self.filtered_logs[idx])

    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.display_page()

    def next_page(self):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.display_page()

    def export_logs(self):
        if not self.filtered_logs:
            show_info(self, "提示", "没有可导出的日志")
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出日志", f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV文件 (*.csv)"
        )
        if filepath:
            try:
                import csv
                with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["时间", "类型", "来源", "事件ID", "级别", "消息"])
                    for log in self.filtered_logs:
                        writer.writerow([log.time_str, log.log_type, log.source, log.event_id, log.level, log.message])
                from ui.report_tab import _show_success_box
                _show_success_box("导出成功", f"已导出 {len(self.filtered_logs)} 条日志到:\n{filepath}", self)
            except Exception as e:
                show_critical(self, "导出失败", f"导出日志失败: {e}")

    def on_activate(self):
        if not self._activated:
            self._activated = True
            cached_logs = self.collector._cached_logs
            if cached_logs:
                self.all_logs = cached_logs
                self.status_label.setText(f"已加载 {len(cached_logs)} 条日志")
                self.apply_filter()

from datetime import datetime