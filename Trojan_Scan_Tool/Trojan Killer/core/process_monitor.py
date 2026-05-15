import psutil
import os
import platform
from datetime import datetime


SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz", "wce", "pwdump", "gsecdump", "fgdump",
    "procdump", "rdpwrap", "hashdump",
    "nc.exe", "netcat", "ncat", "socat",
    "plink.exe",
]

VPN_PROCESSES = [
    "clash", "clashcore", "clashx", "clashforwindows",
    "v2ray", "v2ray-core", "v2rayN", "v2raya",
    "shadowsocks", "ss-local", "ss-server", "ssr",
    "trojan", "trojan-go", "trojan-qt5",
    "psiphon", "lantern", "freedom", "windscribe",
    "expressvpn", "nordvpn", "surfshark", "purevpn",
    "openvpn", "wireguard", "wg",
    "softether", "strongswan", "ikev2",
    "tor", "torbrowser", "torbrowserlauncher",
    "proxifier", "proxycap", "ccproxy",
    "dotsvpn",
    "kuailian", "快连", "kuailianvpn", "快连vpn",
    "tianxing", "天行", "tianxingvpn", "天行vpn",
    "aurora", "极光", "auroravpn", "极光vpn",
    "huojian", "火箭", "huojianvpn", "火箭vpn",
    "laowang", "老王", "laowangvpn", "老王vpn",
    "chuansuo", "穿梭", "chuansuovpn", "穿梭vpn",
    "anyconnect", "ciscoanyconnect",
    "greenvpn", "betternet", "hotspotshield",
    "cyberghost", "privatevpn", "hideme",
    "flyvpn", "speedify", "ivacy", "zenmate",
    "protonvpn", "nord", "express", "surf",
    "vpn",
]

VPN_PORTS = {
    1080, 1081, 1082,  # SOCKS代理
    8080, 8081, 8082,  # HTTP代理
    8443,  # HTTPS代理/Cobalt Strike
    9050, 9051,  # Tor
    51820, 51821,  # WireGuard
    1194,  # OpenVPN
    4444,  # Metasploit/C2
    5555,  # AndroRAT/NjRAT
}

KNOWN_VPN_ASNS = {
    394164,  # ExpressVPN
    393310,  # NordVPN
    395720,  # Surfshark
    201287,  # Private Internet Access
    19995,   # Windscribe
}

SUSPICIOUS_DOMAINS = [
    ".cf", ".ga", ".gq", ".ml", ".tk",
    ".xyz", ".top", ".win", ".vip", ".club",
]

SYSTEM_PROCESSES = [
    "system",
    "registry",
    "memcompression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "dwm.exe",
    "winlogon.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "searchui.exe",
]

HIGH_CONFIDENCE_KEYWORDS = [
    "trojan", "backdoor", "keylog", "payload",
    "exploit", "xmr", "ethminer",
]

LOW_CONFIDENCE_KEYWORDS = [
    "shell", "spy", "coin", "rat", "hack", "crack", "miner",
]

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\windows\\temp\\",
]


class ProcessInfo:
    def __init__(self, proc):
        self.pid = proc.info.get("pid", 0)
        self.name = proc.info.get("name", "") or ""
        self.cpu_percent = 0
        self.memory_mb = 0
        self.username = proc.info.get("username", "") or ""
        self.num_threads = proc.info.get("num_threads", 0) or 0
        self.exe = proc.info.get("exe", "") or ""
        self.cwd = ""
        self.status = proc.info.get("status", "") or ""
        self.create_time = ""
        self.is_suspicious = False
        self.suspicious_reasons = ""

        mem_info = proc.info.get("memory_info")
        if mem_info:
            try:
                self.memory_mb = mem_info.rss / 1024 / 1024
            except Exception:
                self.memory_mb = 0

        ct = proc.info.get("create_time")
        if ct:
            try:
                self.create_time = datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                self.create_time = "N/A"

    def __repr__(self):
        return f"<ProcessInfo pid={self.pid} name={self.name}>"


import threading

class ProcessMonitor:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._all_processes = []
                    cls._instance._process_cache = None
                    cls._instance._process_cache_time = 0
        return cls._instance

    def __init__(self):
        pass

    def get_all_processes(self):
        import time
        now = time.time()
        if self._process_cache is not None and now - self._process_cache_time < 30:
            return self._process_cache

        processes = []

        for proc in psutil.process_iter(["pid", "name", "memory_info",
                                          "username", "num_threads", "exe",
                                          "status", "create_time"]):
            try:
                pinfo = ProcessInfo(proc)
                self._check_suspicious(pinfo)
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._all_processes = processes
        self._process_cache = processes
        self._process_cache_time = now
        return processes

    def get_all_processes_light(self):
        import time
        now = time.time()
        if self._process_cache is not None and now - self._process_cache_time < 30:
            return self._process_cache

        processes = []

        for proc in psutil.process_iter(["pid", "name", "memory_info",
                                          "username", "num_threads", "exe",
                                          "status", "create_time"]):
            try:
                pinfo = ProcessInfo(proc)
                self._check_suspicious(pinfo, check_vpn=False)
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._all_processes = processes
        self._process_cache = processes
        self._process_cache_time = now
        
        self._save_to_db(processes)
        return processes

    def _save_to_db(self, processes):
        try:
            from core.db import DatabaseManager
            db = DatabaseManager()
            db.delete("process_info", "1=1", allow_all=True)
            records = []
            for p in processes:
                records.append({
                    "pid": p.pid,
                    "name": p.name,
                    "path": p.exe or "",
                    "cmdline": getattr(p, 'cmdline', "") or "",
                    "cwd": p.cwd or "",
                    "username": p.username or "",
                    "cpu_usage": p.cpu_percent,
                    "memory_usage": int(p.memory_mb * 1024 * 1024),
                    "thread_count": p.num_threads,
                    "handle_count": getattr(p, 'handle_count', 0),
                    "create_time": p.create_time or "",
                    "suspicious": 1 if p.is_suspicious else 0,
                    "suspicious_reason": p.suspicious_reasons or "",
                })
            if records:
                db.insert_batch("process_info", records)
        except Exception as e:
            print(f"保存进程信息到数据库失败: {e}")

    def _check_suspicious(self, pinfo, check_vpn=True):
        reasons = []

        name_lower = pinfo.name.lower()
        exe_lower = pinfo.exe.lower() if pinfo.exe else ""

        if name_lower in SYSTEM_PROCESSES:
            return

        if name_lower in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("已知恶意工具")

        import re
        has_other_anomaly = False
        for vpn_proc in VPN_PROCESSES:
            pattern = r'(?:^|[\-_])' + re.escape(vpn_proc) + r'(?:$|[\-\._])'
            if re.search(pattern, name_lower):
                reasons.append(f"检测到VPN/代理工具: {vpn_proc}")
                has_other_anomaly = True
                break

        if not has_other_anomaly:
            if "vpn" in name_lower:
                reasons.append("检测到VPN/代理工具")
                has_other_anomaly = True

        for keyword in HIGH_CONFIDENCE_KEYWORDS:
            if keyword in name_lower:
                reasons.append(f"名称含恶意特征: {keyword}")
                break

        has_low_keyword = False
        low_keyword = ""
        for keyword in LOW_CONFIDENCE_KEYWORDS:
            if keyword in name_lower:
                has_low_keyword = True
                low_keyword = keyword
                break

        has_other_anomaly = False
        for path in SUSPICIOUS_PATHS:
            if path in exe_lower:
                clean_path = path.strip("\\")
                reasons.append(f"运行路径可疑: {clean_path}")
                has_other_anomaly = True
                break

        if pinfo.num_threads > 200:
            reasons.append(f"线程数异常({pinfo.num_threads})")
            has_other_anomaly = True

        if pinfo.username and pinfo.username.lower() == "n/a":
            reasons.append("无法获取用户名")
            has_other_anomaly = True

        if pinfo.exe and pinfo.exe != "N/A":
            try:
                if not os.path.exists(pinfo.exe):
                    reasons.append("进程文件不存在")
                    has_other_anomaly = True
            except Exception:
                pass

        if pinfo.exe and "\\appdata\\local\\temp\\" in exe_lower:
            reasons.append("从临时目录运行")
            has_other_anomaly = True

        if has_low_keyword:
            if has_other_anomaly:
                reasons.append(f"名称含敏感词且存在异常: {low_keyword}")
            else:
                pass

        if check_vpn:
            vpn_conn_reason = self._check_vpn_connections(pinfo.pid)
            if vpn_conn_reason:
                reasons.append(vpn_conn_reason)
                has_other_anomaly = True

        if reasons:
            pinfo.is_suspicious = True
            pinfo.suspicious_reasons = "; ".join(reasons)

    def _check_vpn_connections(self, pid):
        try:
            proc = psutil.Process(pid)
            connections = proc.connections(kind="inet")
            
            outbound_count = 0
            vpn_port_count = 0
            suspicious_domains = []
            
            for conn in connections:
                if conn.raddr:
                    outbound_count += 1
                    if conn.raddr.port in VPN_PORTS:
                        vpn_port_count += 1
                    if hasattr(conn.raddr, 'hostname') and conn.raddr.hostname:
                        hostname = conn.raddr.hostname.lower()
                        for domain in SUSPICIOUS_DOMAINS:
                            if hostname.endswith(domain):
                                suspicious_domains.append(hostname)
                                break
            
            if vpn_port_count >= 5:
                return f"大量连接VPN端口({vpn_port_count}个)"
            if len(suspicious_domains) >= 5:
                return f"连接多个可疑域名({len(suspicious_domains)}个)"
            if outbound_count >= 50:
                try:
                    import socket
                    for conn in connections:
                        if conn.raddr:
                            try:
                                hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                                if any(domain in hostname.lower() for domain in ["vpn", "proxy", "tunnel"]):
                                    return f"连接VPN相关服务器"
                            except Exception:
                                pass
                except Exception:
                    pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass
        return None

    def get_process_detail(self, pid):
        try:
            proc = psutil.Process(pid)
            detail = {
                "pid": pid,
                "name": proc.name(),
                "exe": "",
                "cwd": "",
                "username": "",
                "status": proc.status(),
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
                detail["username"] = proc.username()
            except Exception:
                detail["username"] = "N/A"

            try:
                detail["create_time"] = datetime.fromtimestamp(
                    proc.create_time()
                ).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                detail["create_time"] = "N/A"

            try:
                all_connections = list(proc.connections(kind="inet"))
                for conn in all_connections:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    detail["connections"].append({
                        "local": laddr,
                        "remote": raddr,
                        "status": conn.status,
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            except Exception:
                pass

            try:
                all_files = list(proc.open_files())
                total_files = len(all_files)
                for i, f in enumerate(all_files):
                    if i >= 50:
                        break
                    detail["open_files"].append(f.path)
                if total_files > 50:
                    detail["open_files"].append(f"... (还有更多文件)")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            except Exception:
                pass

            return detail

        except psutil.NoSuchProcess:
            return {"error": f"进程 {pid} 不存在"}
        except psutil.AccessDenied:
            return {"error": f"无法访问进程 {pid}，请以管理员身份运行"}
        except Exception as e:
            return {"error": str(e)}

    def get_process_by_ip(self, target_ip):
        results = []
        seen = set()

        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            if conn.raddr.ip != target_ip:
                continue

            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                if not proc:
                    continue

                key = f"{conn.pid}_{conn.raddr.ip}_{conn.raddr.port}"
                if key in seen:
                    continue
                seen.add(key)

                result = {
                    "pid": conn.pid,
                    "process_name": proc.name(),
                    "process_path": proc.exe(),
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "username": proc.username(),
                    "create_time": datetime.fromtimestamp(
                        proc.create_time()
                    ).strftime("%Y-%m-%d %H:%M:%S") if proc.create_time() else "N/A",
                }
                results.append(result)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return results

    def kill_process(self, pid, force=False):
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()
            return True, "成功"
        except psutil.NoSuchProcess:
            return False, "进程不存在"
        except psutil.AccessDenied:
            return False, "权限不足，请以管理员身份运行"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _get_os_version():
        try:
            ver = platform.version()
            edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
            parts = ver.split(".")
            build = int(parts[-1]) if len(parts) >= 3 and parts[-1].isdigit() else 0
            if build >= 22000:
                base = "Windows 11"
            elif build >= 10240:
                base = "Windows 10"
            else:
                base = platform.system()
            if edition:
                edition_map = {
                    "Professional": "专业版",
                    "ProfessionalEducation": "专业教育版",
                    "ProfessionalWorkstation": "专业工作站版",
                    "Enterprise": "企业版",
                    "Education": "教育版",
                    "Home": "家庭版",
                    "Core": "家庭版",
                    "CoreSingleLanguage": "家庭中文版",
                    "CoreCountrySpecific": "家庭中文版",
                    "IoTEnterprise": "IoT 企业版",
                    "ServerStandard": "Server 标准版",
                    "ServerDatacenter": "Server 数据中心版",
                }
                display_edition = edition_map.get(edition, edition)
                return f"{base} {display_edition} (版本 {build})"
            major = parts[1] if len(parts) >= 2 else "0"
            return f"{base} (版本 {major}.{build})"
        except Exception:
            try:
                return platform.platform()
            except Exception:
                return "Windows"

    @staticmethod
    def _get_network_info():
        try:
            import socket
            hostname = socket.gethostname()
            ips = []
            macs = []
            virtual_keywords = [
                "vmware", "virtualbox", "hyper-v", "vbox", "virtual",
                "vpn", "tap", "npcap", "loopback",
                "pseudo", "isatap", "teredo", "6to4",
                "wsl", "docker", "nat", "vethernet",
                "pve", "bridge", "ppp", "nlb", "team",
                "wi-fi direct", "microsoft wifi",
                "bluetooth", "蓝牙",
            ]
            stats_map = {}
            try:
                stats_map = psutil.net_if_stats()
            except Exception:
                pass
            for iface, addrs in psutil.net_if_addrs().items():
                iface_lower = iface.lower()
                if any(k in iface_lower for k in virtual_keywords):
                    continue
                stats = stats_map.get(iface)
                if stats is not None and not stats.isup:
                    continue
                has_ip = False
                has_mac = False
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ips.append({"interface": iface, "address": addr.address})
                        has_ip = True
                    if addr.family == psutil.AF_LINK and addr.address not in ("00:00:00:00:00:00", ""):
                        macs.append({"interface": iface, "address": addr.address})
                        has_mac = True
                if not has_ip and not has_mac:
                    continue
            return {
                "hostname": hostname,
                "ips": ips,
                "macs": macs,
            }
        except Exception:
            return {"hostname": "", "ips": [], "macs": []}

    def get_system_info(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            boot_time = datetime.fromtimestamp(
                psutil.boot_time()
            ).strftime("%Y-%m-%d %H:%M:%S")

            disk_list = []
            max_percent = 0
            max_disk = None
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    info = {
                        "mount": part.mountpoint,
                        "percent": usage.percent,
                        "used": round(usage.used / 1024**3, 1),
                        "total": round(usage.total / 1024**3, 1),
                        "fstype": part.fstype,
                    }
                    disk_list.append(info)
                    if usage.percent > max_percent:
                        max_percent = usage.percent
                        max_disk = info
                except Exception:
                    continue

            if not max_disk:
                max_disk = {"mount": "N/A", "percent": 0, "used": 0, "total": 0}

            net_info = self._get_network_info()

            return {
                "process_count": len(self._all_processes) if self._all_processes else len(psutil.pids()),
                "cpu_percent": cpu_percent,
                "cpu_count": psutil.cpu_count(),
                "memory_percent": memory.percent,
                "memory_used": round(memory.used / 1024**3, 1),
                "memory_total": round(memory.total / 1024**3, 1),
                "disk_percent": max_disk["percent"],
                "disk_used": max_disk["used"],
                "disk_total": max_disk["total"],
                "disks": disk_list,
                "boot_time": boot_time,
                "os_version": self._get_os_version(),
                "hostname": net_info["hostname"],
                "ip_addresses": net_info["ips"],
                "mac_addresses": net_info["macs"],
            }
        except Exception as e:
            return {
                "process_count": 0,
                "cpu_percent": 0,
                "cpu_count": 0,
                "memory_percent": 0,
                "memory_used": 0,
                "memory_total": 0,
                "disk_percent": 0,
                "disk_used": 0,
                "disk_total": 0,
                "disks": [],
                "boot_time": str(e),
                "os_version": "N/A",
                "hostname": "",
                "ip_addresses": [],
                "mac_addresses": [],
            }
