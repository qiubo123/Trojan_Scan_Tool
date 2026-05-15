import subprocess
import re
from datetime import datetime


class UserInfo:
    def __init__(self):
        self.name = ""
        self.full_name = ""
        self.sid = ""
        self.disabled = False
        self.is_suspicious = False
        self.suspicious_reasons = []
        self.last_login = ""

    def __repr__(self):
        return f"<UserInfo {self.name}>"


import threading

class UserChecker:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.users = []
                    cls._instance._cache_time = 0
                    cls._instance._groups_cache = None
                    cls._instance._groups_cache_time = 0
        return cls._instance

    def __init__(self):
        pass

    def get_all_users(self):
        import time
        now = time.time()
        if self.users and now - self._cache_time < 30:
            return self.users

        users = []

        try:
            result = subprocess.run(
                ["wmic", "useraccount", "get", "name,fullname,sid,disabled,status",
                 "/format:csv"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    parts = line.split(",")
                    if len(parts) >= 6:
                        user = UserInfo()
                        user.disabled = parts[1].strip().lower() in ("true", "yes", "1")
                        user.full_name = parts[2].strip() if len(parts) > 2 else ""
                        user.name = parts[3].strip() if len(parts) > 3 else ""
                        user.sid = parts[4].strip() if len(parts) > 4 else ""

                        self._check_suspicious(user)
                        users.append(user)

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,FullName | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0 and result.stdout.strip():
                    import json
                    data = json.loads(result.stdout.strip())
                    if not isinstance(data, list):
                        data = [data]
                    for item in data:
                        user = UserInfo()
                        user.name = item.get("Name", "")
                        user.sid = item.get("SID", "")
                        user.disabled = not item.get("Enabled", True)
                        user.full_name = item.get("FullName", "") or ""

                        last_logon = item.get("LastLogon")
                        if last_logon:
                            user.last_login = self._parse_dotnet_date(str(last_logon))

                        self._check_suspicious(user)
                        users.append(user)
            except Exception:
                pass

        try:
            self._fill_last_login_with_powershell(users)
        except Exception:
            pass

        self.users = users
        self._cache_time = now

        if users:
            self._save_to_db(users)
        return users

    @staticmethod
    def _parse_dotnet_date(val):
        import re
        m = re.search(r'/Date\((\d+)\)/', val)
        if m:
            try:
                timestamp_ms = int(m.group(1))
                dt = datetime.fromtimestamp(timestamp_ms / 1000)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
        return val

    def _fill_last_login_with_powershell(self, users):
        name_map = {}
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-LocalUser | Select-Object Name,LastLogon | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout.strip())
                if not isinstance(data, list):
                    data = [data]
                for item in data:
                    name = item.get("Name", "").lower()
                    ll = item.get("LastLogon")
                    if ll and name:
                        name_map[name] = self._parse_dotnet_date(str(ll))

                for user in users:
                    key = user.name.lower()
                    if key in name_map:
                        user.last_login = name_map[key]
        except Exception:
            pass

    def _save_to_db(self, users):
        try:
            from core.db import DatabaseManager
            db = DatabaseManager()
            db.delete("user_accounts", "1=1", allow_all=True)
            records = []
            for user in users:
                records.append({
                    "name": user.name or "",
                    "full_name": user.full_name or "",
                    "sid": user.sid or "",
                    "status": "禁用" if user.disabled else "启用",
                    "is_admin": 1 if getattr(user, 'is_admin', False) else 0,
                    "is_suspicious": 1 if user.is_suspicious else 0,
                    "suspicious_reason": "; ".join(user.suspicious_reasons) if user.suspicious_reasons else "",
                    "last_login": user.last_login,
                })
            if records:
                db.insert_batch("user_accounts", records)
        except Exception as e:
            print(f"保存用户账户到数据库失败: {e}")

    def _check_suspicious(self, user):
        reasons = []

        system_accounts = [
            "administrator", "guest", "defaultaccount",
            "wdagutilityaccount", "defaultuser0", "defaultuser1",
            "homegroupuser$", "iusr", "iwam", "localservice",
            "networkservice", "systemprofile", "localsystem",
        ]

        if user.name.lower() in system_accounts:
            if user.disabled:
                return
            if user.name.lower() in ["guest", "defaultaccount"]:
                reasons.append(f"系统默认账户应禁用: {user.name}")
            return

        if user.name.lower() in ["test", "temp", "debug"]:
            reasons.append("测试/临时账户")

        if user.name and len(user.name) > 20:
            reasons.append("用户名过长，可能是自动生成")

        if user.name.lower().startswith("admin") and not user.disabled:
            reasons.append("管理员账户未禁用")

        if reasons:
            user.is_suspicious = True
            user.suspicious_reasons = reasons

    def get_user_statistics(self):
        users = self.get_all_users()

        total = len(users)
        enabled = sum(1 for u in users if not u.disabled)
        disabled = sum(1 for u in users if u.disabled)
        suspicious = sum(1 for u in users if u.is_suspicious)

        return {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "suspicious": suspicious,
        }

    def get_user_groups(self):
        import time
        now = time.time()
        if self._groups_cache is not None and now - self._groups_cache_time < 30:
            return self._groups_cache

        groups = []

        try:
            result = subprocess.run(
                ["wmic", "group", "get", "name,sid", "/format:csv"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    parts = line.split(",")
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        sid = parts[2].strip() if len(parts) > 2 else ""
                        groups.append({
                            "name": name,
                            "sid": sid,
                        })
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-LocalGroup | Select-Object Name,Description | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0 and result.stdout.strip():
                    import json
                    data = json.loads(result.stdout.strip())
                    if not isinstance(data, list):
                        data = [data]
                    for item in data:
                        groups.append({
                            "name": item.get("Name", ""),
                            "sid": "",
                        })
            except Exception:
                pass

        self._groups_cache = groups
        self._groups_cache_time = now
        return groups
