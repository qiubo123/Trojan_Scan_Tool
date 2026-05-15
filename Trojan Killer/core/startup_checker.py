import os
import winreg
import subprocess
from datetime import datetime


STARTUP_REGISTRY_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
]

SUSPICIOUS_STARTUP_KEYWORDS = [
    "hack", "crack", "rat", "trojan", "backdoor",
    "miner", "coin", "payload",
]

SUSPICIOUS_STARTUP_NAMES = [
    "mshta", "certutil", "bitsadmin",
]


class StartupItem:
    def __init__(self, item_type, name, location, command):
        self.item_type = item_type
        self.name = name
        self.location = location
        self.command = command
        self.is_suspicious = False
        self.suspicious_reasons = []

    def __repr__(self):
        return f"<StartupItem {self.item_type} {self.name}>"


import threading

class StartupChecker:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.items = []
                    cls._instance._cache_time = 0
        return cls._instance

    def __init__(self):
        pass

    def check_registry(self):
        items = []
        for hkey, subkey in STARTUP_REGISTRY_PATHS:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if name and value:
                                item = StartupItem(
                                    "注册表", name,
                                    f"{'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{subkey}",
                                    value
                                )
                                self._check_suspicious(item)
                                items.append(item)
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except (OSError, PermissionError):
                continue
        return items

    def check_startup_folder(self):
        items = []
        startup_paths = [
            os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                         "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.path.join(os.environ.get("APPDATA", ""),
                         "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.environ.get("ALLUSERSPROFILE", ""),
        ]

        for startup_path in startup_paths:
            if not startup_path or not os.path.exists(startup_path):
                continue
            try:
                for filename in os.listdir(startup_path):
                    filepath = os.path.join(startup_path, filename)
                    if os.path.isfile(filepath):
                        item = StartupItem(
                            "启动文件夹", filename,
                            startup_path, filepath
                        )
                        self._check_suspicious(item)
                        items.append(item)
            except (PermissionError, OSError):
                continue

        return items

    def check_scheduled_tasks(self):
        items = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = result.stdout.strip().split("\n")
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    task_name = parts[0].strip().strip('"')
                    task_command = parts[-1].strip().strip('"') if len(parts) > 1 else ""
                    if task_name and task_command:
                        item = StartupItem(
                            "计划任务",
                            task_name.split("\\")[-1],
                            task_name,
                            task_command
                        )
                        self._check_suspicious(item)
                        items.append(item)

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass

        return items

    def check_services(self):
        items = []
        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = result.stdout.split("\n")
            current_service = {}

            for line in lines:
                line = line.strip()
                if line.startswith("SERVICE_NAME"):
                    if current_service.get("SERVICE_NAME") and current_service.get("DISPLAY_NAME"):
                        item = StartupItem(
                            "系统服务",
                            current_service.get("DISPLAY_NAME", ""),
                            current_service.get("SERVICE_NAME", ""),
                            current_service.get("BINARY_PATH_NAME", "")
                        )
                        self._check_suspicious(item)
                        items.append(item)
                    current_service = {"SERVICE_NAME": line.split(":")[-1].strip()}
                elif ":" in line:
                    key, _, value = line.partition(":")
                    current_service[key.strip()] = value.strip()

            if current_service.get("SERVICE_NAME") and current_service.get("DISPLAY_NAME"):
                item = StartupItem(
                    "系统服务",
                    current_service.get("DISPLAY_NAME", ""),
                    current_service.get("SERVICE_NAME", ""),
                    current_service.get("BINARY_PATH_NAME", "")
                )
                self._check_suspicious(item)
                items.append(item)

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass

        return items

    def _check_suspicious(self, item):
        reasons = []
        name_lower = item.name.lower()
        command_lower = item.command.lower()

        if name_lower in SUSPICIOUS_STARTUP_NAMES:
            reasons.append(f"名称伪装: {item.name}")

        for keyword in SUSPICIOUS_STARTUP_KEYWORDS:
            if keyword in command_lower:
                reasons.append(f"命令路径含敏感词: {keyword}")
                break

        suspicious_dirs = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]
        for d in suspicious_dirs:
            if d in command_lower:
                clean_d = d.strip("\\")
                reasons.append(f"从临时目录启动: {clean_d}")
                break

        if "powershell" in command_lower and ("-enc" in command_lower or "-e " in command_lower):
            reasons.append("PowerShell编码执行")

        if "rundll32" in command_lower and "javascript" in command_lower:
            reasons.append("Rundll32执行JavaScript")

        if "mshta" in command_lower:
            reasons.append("Mshta执行脚本")

        if "certutil" in command_lower and "-decode" in command_lower:
            reasons.append("Certutil解码执行")

        if reasons:
            item.is_suspicious = True
            item.suspicious_reasons = reasons

    def check_all(self):
        import time
        now = time.time()
        if self.items and now - self._cache_time < 30:
            return self.items

        items = []
        items.extend(self.check_registry())
        items.extend(self.check_startup_folder())
        items.extend(self.check_scheduled_tasks())
        self.items = items
        self._cache_time = now
        
        self._save_to_db(items)
        return items

    def _save_to_db(self, items):
        try:
            from core.db import DatabaseManager
            db = DatabaseManager()
            db.delete("startup_items", "1=1", allow_all=True)
            records = []
            for item in items:
                records.append({
                    "name": item.name or "",
                    "path": getattr(item, 'path', "") or "",
                    "command": item.command or "",
                    "location": item.location or "",
                    "startup_type": item.item_type or "",
                    "publisher": getattr(item, 'publisher', "") or "",
                    "status": getattr(item, 'status', "") or "",
                })
            if records:
                db.insert_batch("startup_items", records)
        except Exception as e:
            print(f"保存启动项到数据库失败: {e}")
