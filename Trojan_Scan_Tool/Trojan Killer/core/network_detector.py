import psutil
import socket
from datetime import datetime
from .malicious_ip import MaliciousIPManager


class ConnectionInfo:
    def __init__(self, conn, process_name=""):
        self.protocol = "tcp"
        self.laddr = conn.laddr
        self.raddr = conn.raddr
        self.status = conn.status
        self.pid = conn.pid
        self.process_name = process_name
        self.process_path = ""
        self.process_cmdline = ""
        self.process_cwd = ""
        self.process_create_time = ""
        self.is_malicious = False

        if conn.type == socket.SOCK_DGRAM:
            self.protocol = "udp"

    def __repr__(self):
        return f"<ConnectionInfo {self.raddr}>"


import threading

class NetworkDetector:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.malicious_mgr = MaliciousIPManager()
                    cls._instance._process_cache = {}
                    cls._instance._malicious_cache = None
                    cls._instance._malicious_cache_time = 0
                    cls._instance._connections_cache = None
                    cls._instance._connections_cache_time = 0
        return cls._instance

    def __init__(self):
        pass

    def _get_process_name(self, pid):
        if pid is None or pid == 0:
            return ""
        if pid in self._process_cache:
            return self._process_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            if len(self._process_cache) > 500:
                self._process_cache.clear()
            self._process_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._process_cache[pid] = ""
            return ""

    def _fill_process_detail(self, info):
        if info.pid is None or info.pid == 0:
            return
        try:
            proc = psutil.Process(info.pid)
            try:
                info.process_path = proc.exe()
            except Exception:
                info.process_path = ""
            try:
                info.process_cmdline = " ".join(proc.cmdline())
            except Exception:
                info.process_cmdline = ""
            try:
                info.process_cwd = proc.cwd()
            except Exception:
                info.process_cwd = ""
            try:
                info.process_create_time = datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                info.process_create_time = ""
        except Exception:
            pass

    def _get_malicious_ips(self):
        import time
        now = time.time()
        if self._malicious_cache is not None and now - self._malicious_cache_time < 30:
            return self._malicious_cache
        ips = self.malicious_mgr.get_all_black_ips()
        ip_set = set()
        for ip in ips:
            ip_set.add(ip["ip"])
        self._malicious_cache = ip_set
        self._malicious_cache_time = now
        return ip_set

    def _get_cached_connections(self):
        import time
        now = time.time()
        if self._connections_cache is not None and now - self._connections_cache_time < 2:
            return self._connections_cache
        self._connections_cache = list(psutil.net_connections(kind="inet"))
        self._connections_cache_time = now
        return self._connections_cache

    def get_external_connections(self):
        connections = []
        malicious_ips = self._get_malicious_ips()

        for conn in self._get_cached_connections():
            try:
                if not conn.raddr:
                    continue

                if conn.raddr.ip and conn.raddr.ip.startswith(("127.", "192.168.", "10.", "172.16.")):
                    continue

                if conn.raddr.ip in ("0.0.0.0", "::"):
                    continue

                process_name = self._get_process_name(conn.pid)
                info = ConnectionInfo(conn, process_name)
                self._fill_process_detail(info)

                if conn.raddr.ip in malicious_ips:
                    info.is_malicious = True

                connections.append(info)

            except Exception:
                continue

        return connections

    def get_connection_statistics(self):
        try:
            total = 0
            established = 0
            listening = 0
            time_wait = 0
            close_wait = 0
            malicious_count = 0
            malicious_ips = self._get_malicious_ips()

            for conn in self._get_cached_connections():
                total += 1
                if conn.status == "ESTABLISHED":
                    established += 1
                elif conn.status == "LISTEN":
                    listening += 1
                elif conn.status == "TIME_WAIT":
                    time_wait += 1
                elif conn.status == "CLOSE_WAIT":
                    close_wait += 1

                if conn.raddr and conn.raddr.ip in malicious_ips:
                    malicious_count += 1

            return {
                "total": total,
                "established": established,
                "listening": listening,
                "time_wait": time_wait,
                "close_wait": close_wait,
                "malicious": malicious_count,
            }

        except Exception as e:
            return {
                "total": 0,
                "established": 0,
                "listening": 0,
                "time_wait": 0,
                "close_wait": 0,
                "malicious": 0,
            }

    def scan_malicious_ips(self):
        threats = []
        malicious_ips = self._get_malicious_ips()

        for conn in self._get_cached_connections():
            try:
                if not conn.raddr:
                    continue

                if conn.raddr.ip not in malicious_ips:
                    continue

                process_name = self._get_process_name(conn.pid)

                threat = {
                    "threat_type": "恶意IP连接",
                    "threat_name": f"连接到恶意IP: {conn.raddr.ip}",
                    "threat_ip": conn.raddr.ip,
                    "threat_port": conn.raddr.port,
                    "risk_level": "高危",
                    "process_name": process_name,
                    "process_pid": conn.pid or 0,
                    "description": f"进程 {process_name}(PID:{conn.pid}) 连接到恶意IP {conn.raddr.ip}:{conn.raddr.port}",
                    "suggestion": "请检查该进程是否为木马，建议结束进程并删除对应文件",
                }
                threats.append(threat)

            except Exception:
                continue

        return threats

    def log_connections(self, connections):
        from .db import DatabaseManager
        db = DatabaseManager()
        count = 0
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for conn in connections:
            try:
                local_ip = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                remote_ip = conn.raddr.ip if conn.raddr else ""
                remote_port = conn.raddr.port if conn.raddr else 0
                db.insert("connection_log", {
                    "log_time": now_str,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": conn.protocol,
                    "status": conn.status or "",
                    "pid": conn.pid or 0,
                    "process_name": conn.process_name,
                    "process_path": conn.process_path,
                    "process_cmdline": conn.process_cmdline,
                    "process_cwd": conn.process_cwd,
                    "process_create_time": conn.process_create_time,
                    "is_malicious": 1 if conn.is_malicious else 0,
                })
                count += 1
            except Exception:
                continue
        return count
