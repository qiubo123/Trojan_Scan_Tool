MAIN_STYLE = """
QMainWindow {
    background-color: #1a1a2e;
}

QWidget {
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
    color: #e0e0e0;
}

#statCard {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
}

#statCard:hover {
    border-color: #e94560;
}

QMenuBar {
    background-color: #16213e;
    color: #e0e0e0;
    border-bottom: 1px solid #0f3460;
    padding: 2px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QMenuBar::item:selected {
    background-color: #0f3460;
}

QMenu {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QMenu::item:selected {
    background-color: #0f3460;
}

QTabWidget::pane {
    border: 1px solid #0f3460;
    background-color: #1a1a2e;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #16213e;
    color: #a0a0a0;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QTabBar::tab:selected {
    background-color: #0f3460;
    color: #e94560;
    border-bottom: 2px solid #e94560;
}

QTabBar::tab:hover:!selected {
    background-color: #1a3a6a;
    color: #e0e0e0;
}

QTableWidget {
    background-color: #16213e;
    alternate-background-color: #1a2744;
    border: 1px solid #0f3460;
    border-radius: 4px;
    gridline-color: #0f3460;
    selection-background-color: #0f3460;
    selection-color: #e94560;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QTableWidget::item {
    padding: 4px 8px;
}

QTableWidget::item:selected {
    background-color: #0f3460;
    color: #e94560;
}

QHeaderView::section {
    background-color: #0f3460;
    color: #e0e0e0;
    padding: 6px;
    border: none;
    border-right: 1px solid #1a1a2e;
    border-bottom: 1px solid #1a1a2e;
    font-weight: bold;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QTreeWidget {
    background-color: #16213e;
    alternate-background-color: #1a2744;
    border: 1px solid #0f3460;
    border-radius: 4px;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QTreeWidget::item:selected {
    background-color: #0f3460;
    color: #e94560;
}

QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    padding: 6px 16px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    min-height: 24px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QPushButton:hover {
    background-color: #1a4a8a;
}

QPushButton:pressed {
    background-color: #0a2540;
}

QPushButton:disabled {
    background-color: #2a2a3e;
    color: #606060;
}

QPushButton#dangerBtn {
    background-color: #e94560;
    color: white;
}

QPushButton#dangerBtn:hover {
    background-color: #c73a52;
}

QPushButton#successBtn {
    background-color: #27ae60;
    color: white;
}

QPushButton#successBtn:hover {
    background-color: #219653;
}

QPushButton#warningBtn {
    background-color: #f39c12;
    color: white;
}

QPushButton#warningBtn:hover {
    background-color: #d68910;
}

QLabel {
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QLabel#titleLabel {
    font-size: 16px;
    font-weight: bold;
    color: #e94560;
}

QLabel#statusLabel {
    font-size: 11px;
    color: #a0a0a0;
}

QGroupBox {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 16px;
    font-size: 13px;
    font-weight: bold;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #e94560;
}

QLineEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QLineEdit:focus {
    border-color: #e94560;
}

QTextEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Consolas", "Courier New", monospace;
}

QComboBox {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    font-size: 12px;
    min-width: 100px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid #e0e0e0;
    margin-right: 5px;
}

QComboBox:hover {
    border-color: #e94560;
}

QComboBox QAbstractItemView {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    selection-background-color: #0f3460;
    selection-color: #e94560;
    outline: none;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QComboBox QAbstractItemView::item {
    padding: 6px 10px;
    min-height: 24px;
}

QComboBox QAbstractItemView::item:hover {
    background-color: #0f3460;
    color: #e94560;
}

QSpinBox, QDoubleSpinBox, QDateTimeEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 4px 6px;
    color: #e0e0e0;
    font-size: 12px;
    min-height: 24px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QSpinBox:focus, QDoubleSpinBox:focus, QDateTimeEdit:focus {
    border-color: #e94560;
}

QSpinBox::up-button, QDoubleSpinBox::up-button {
    background-color: #0f3460;
    border: none;
    border-left: 1px solid #0d1b3e;
    border-bottom: 1px solid #0d1b3e;
    width: 18px;
    border-top-right-radius: 3px;
}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover {
    background-color: #1a4a8a;
}

QSpinBox::down-button, QDoubleSpinBox::down-button {
    background-color: #0f3460;
    border: none;
    border-left: 1px solid #0d1b3e;
    width: 18px;
    border-bottom-right-radius: 3px;
}

QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
    background-color: #1a4a8a;
}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
    width: 0;
    height: 0;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid #e0e0e0;
}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
    width: 0;
    height: 0;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #e0e0e0;
}

QProgressBar {
    border: 1px solid #0f3460;
    border-radius: 4px;
    text-align: center;
    color: #e0e0e0;
    font-size: 11px;
    background-color: #0d1b3e;
    height: 20px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QProgressBar::chunk {
    background-color: #e94560;
    border-radius: 3px;
}

QCheckBox {
    color: #e0e0e0;
    font-size: 12px;
    spacing: 6px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #0f3460;
    border-radius: 3px;
    background-color: #0d1b3e;
}

QCheckBox::indicator:checked {
    background-color: #e94560;
    border-color: #e94560;
}

QRadioButton {
    color: #e0e0e0;
    font-size: 12px;
    spacing: 6px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QSplitter::handle {
    background-color: #0f3460;
    width: 2px;
}

QScrollBar:vertical {
    background-color: #0d1b3e;
    width: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #0f3460;
    border-radius: 5px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #1a4a8a;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #0d1b3e;
    height: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #0f3460;
    border-radius: 5px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #1a4a8a;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QStatusBar {
    background-color: #16213e;
    color: #a0a0a0;
    border-top: 1px solid #0f3460;
    font-size: 11px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QStatusBar::item {
    border: none;
}

QMessageBox {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QMessageBox QLabel {
    color: #e0e0e0;
    font-size: 13px;
    min-width: 200px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QMessageBox QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    padding: 6px 20px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    min-width: 80px;
    min-height: 28px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QMessageBox QPushButton:hover {
    background-color: #1a4a8a;
}

QDialog {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QLabel {
    color: #e0e0e0;
    font-size: 13px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QLineEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QLineEdit:focus {
    border-color: #e94560;
}

QDialog QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    padding: 6px 20px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    min-width: 80px;
    min-height: 28px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QPushButton:hover {
    background-color: #1a4a8a;
}

QDialog QComboBox {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QComboBox QAbstractItemView {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    selection-background-color: #0f3460;
    selection-color: #e94560;
    outline: none;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QComboBox QAbstractItemView::item {
    padding: 6px 10px;
    min-height: 24px;
}

QDialog QComboBox QAbstractItemView::item:hover {
    background-color: #0f3460;
    color: #e94560;
}

QDialog QSpinBox, QDialog QDoubleSpinBox {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 4px 6px;
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QGroupBox {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 16px;
    font-size: 13px;
    font-weight: bold;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #e94560;
}

QDialog QTableWidget {
    background-color: #16213e;
    alternate-background-color: #1a2744;
    border: 1px solid #0f3460;
    border-radius: 4px;
    gridline-color: #0f3460;
    selection-background-color: #0f3460;
    selection-color: #e94560;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QDialog QHeaderView::section {
    background-color: #0f3460;
    color: #e0e0e0;
    padding: 6px;
    border: none;
    border-right: 1px solid #1a1a2e;
    border-bottom: 1px solid #1a1a2e;
    font-weight: bold;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog QLabel {
    color: #e0e0e0;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog QLineEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 4px 8px;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    padding: 4px 14px;
    border-radius: 4px;
    font-size: 12px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog QPushButton:hover {
    background-color: #1a4a8a;
}

QFileDialog QTreeView {
    background-color: #16213e;
    color: #e0e0e0;
    alternate-background-color: #1a2744;
    border: 1px solid #0f3460;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QFileDialog QTreeView::item:selected {
    background-color: #0f3460;
    color: #e94560;
}

QFileDialog QComboBox {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 4px 8px;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QInputDialog {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QInputDialog QLabel {
    color: #e0e0e0;
    font-size: 13px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QInputDialog QLineEdit {
    background-color: #0d1b3e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QInputDialog QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    padding: 6px 20px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    min-width: 80px;
    min-height: 28px;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QInputDialog QPushButton:hover {
    background-color: #1a4a8a;
}
"""

CARD_STYLE = """
QFrame#card {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 12px;
}

QFrame#card:hover {
    border-color: #e94560;
}
"""

CARD_TITLE_STYLE = "font-size: 11px; color: #a0a0a0;"
CARD_VALUE_STYLE = "font-size: 24px; font-weight: bold; color: #e94560;"
CARD_VALUE_GREEN_STYLE = "font-size: 24px; font-weight: bold; color: #27ae60;"
CARD_VALUE_YELLOW_STYLE = "font-size: 24px; font-weight: bold; color: #f39c12;"
