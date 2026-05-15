import subprocess
import winreg
import re
import threading

VPN_PROGRAMS = [
    "clash", "clashx", "clashforwindows", "clashcore",
    "v2ray", "v2rayn", "v2raya", "v2fly",
    "shadowsocks", "ssr", "shadowsock",
    "trojan", "trojan-qt5", "trojan-go",
    "psiphon", "lantern", "freedom", "windscribe",
    "expressvpn", "nordvpn", "surfshark", "purevpn",
    "openvpn", "wireguard", "wg",
    "softether", "strongswan", "ikev2",
    "tor", "torbrowser",
    "proxifier", "proxycap", "ccproxy",
    "greenvpn", "betternet", "hotspot shield",
    "cyberghost", "privatevpn", "hide.me",
    "avast secureline", "avg secure vpn", "mcafee safe connect",
    "norton secure vpn", "kaspersky secure connection",
    "dotsvpn",
    "kuailian", "快连", "kuailianvpn", "快连vpn",
    "tianxing", "天行", "tianxingvpn", "天行vpn",
    "aurora", "极光", "auroravpn", "极光vpn",
    "huojian", "火箭", "huojianvpn", "火箭vpn",
    "laowang", "老王", "laowangvpn", "老王vpn",
    "chuansuo", "穿梭", "chuansuovpn", "穿梭vpn",
    "anyconnect", "ciscoanyconnect",
    "flyvpn", "speedify", "ivacy", "zenmate",
    "protonvpn", "nord", "express", "surf",
    "vpn",
]


class SoftwareScanner:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.programs = []
                    cls._instance._cache_time = 0
        return cls._instance

    def __init__(self):
        pass

    def scan(self):
        import time
        now = time.time()
        if self.programs and now - self._cache_time < 30:
            return self.programs

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

                        try:
                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                        except FileNotFoundError:
                            install_location = ""

                        try:
                            uninstall_string = winreg.QueryValueEx(subkey, "UninstallString")[0]
                        except FileNotFoundError:
                            uninstall_string = ""

                        try:
                            estimated_size = winreg.QueryValueEx(subkey, "EstimatedSize")[0]
                            size_mb = round(estimated_size / 1024, 1) if estimated_size else 0
                        except FileNotFoundError:
                            size_mb = 0

                        programs.append({
                            "name": name,
                            "version": version,
                            "publisher": publisher,
                            "install_date": install_date,
                            "install_location": install_location,
                            "uninstall_string": uninstall_string,
                            "size_mb": size_mb,
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
                        "install_location": "",
                        "uninstall_string": "",
                        "size_mb": 0,
                    })
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass

        programs.sort(key=lambda x: x["name"].lower())
        self.programs = programs
        self._cache_time = now
        
        self._save_to_db(programs)
        return programs

    def _save_to_db(self, programs):
        try:
            from core.db import DatabaseManager
            db = DatabaseManager()
            db.delete("software_info", "1=1", allow_all=True)
            records = []
            for prog in programs:
                records.append({
                    "name": prog["name"] or "",
                    "version": prog["version"] or "",
                    "publisher": prog["publisher"] or "",
                    "install_date": prog["install_date"] or "",
                    "install_location": prog["install_location"] or "",
                    "uninstall_string": prog["uninstall_string"] or "",
                    "size_mb": prog["size_mb"] or 0,
                    "is_vpn": 1 if self.is_vpn_program(prog["name"]) else 0,
                })
            if records:
                db.insert_batch("software_info", records)
        except Exception as e:
            print(f"保存软件信息到数据库失败: {e}")

    def is_vpn_program(self, name):
        name_lower = name.lower()
        for vpn in VPN_PROGRAMS:
            if vpn in name_lower:
                return True
        return False


def get_installed_programs():
    scanner = SoftwareScanner()
    return scanner.scan()
