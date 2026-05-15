from PyQt6.QtWidgets import QMessageBox, QLabel
from PyQt6.QtCore import Qt


def _config_msg(msg):
    layout = msg.layout()
    if layout:
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), QLabel):
                label = item.widget()
                label.setWordWrap(True)
                label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                label.setMaximumWidth(600)
                break


def show_info(parent, title, text):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle(title)
    msg.setText(text)
    _config_msg(msg)
    msg.exec()


def show_warning(parent, title, text):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle(title)
    msg.setText(text)
    _config_msg(msg)
    msg.exec()


def show_critical(parent, title, text):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle(title)
    msg.setText(text)
    _config_msg(msg)
    msg.exec()


def show_question(parent, title, text):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    _config_msg(msg)
    return msg.exec()


def show_about(parent, title, text):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.NoIcon)
    msg.setWindowTitle("关于")
    msg.setText(title)
    msg.setInformativeText(text)
    _config_msg(msg)
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    msg.exec()
