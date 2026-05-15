# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(r"D:\木马病毒查杀工具")

block_cipher = None

a = Analysis(
    [str(PROJECT_ROOT / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "PyQt6",
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "psutil",
        "core.db",
        "core.malicious_ip",
        "core.process_monitor",
        "core.network_detector",
        "core.connection_logger",
        "core.log_collector",
        "core.startup_checker",
        "core.user_checker",
        "ui.main_window",
        "ui.dashboard_tab",
        "ui.process_tab",
        "ui.connection_tab",
        "ui.log_tab",
        "ui.report_tab",
        "ui.startup_tab",
        "ui.user_tab",
        "ui.software_tab",
        "ui.threat_intel_tab",
        "ui.styles",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "server",
        "tkinter",
        "test",
        "distutils",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="恶意外联排查工具",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT_ROOT / "app.ico") if (PROJECT_ROOT / "app.ico").exists() else None,
)
