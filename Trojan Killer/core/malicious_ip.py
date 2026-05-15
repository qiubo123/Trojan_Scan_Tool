import json
import os
import socket
import struct
import hashlib
import hmac
import urllib.request
import urllib.parse
import subprocess
import re
from datetime import datetime

from .db import DatabaseManager, get_data_dir

DATA_DIR = get_data_dir()
BUILTIN_IP_FILE = os.path.join(DATA_DIR, "malicious_ips.json")

BUILTIN_MALICIOUS_IPS = {
    "known_c2": [
        {"ip": "198.135.49.79", "port": 443, "threat_type": "后门", "description": "RemCos远控木马,可执行键盘记录、截屏、密码窃取", "location": "美国/德克萨斯州/达拉斯", "tags": "RemCos,后门,远控"},
        {"ip": "178.162.217.107", "port": 80, "threat_type": "僵尸网络", "description": "MooBot(Mirai变种),利用IoT漏洞组建僵尸网络发起DDoS", "location": "德国/黑森州/美因河畔法兰克福", "tags": "MooBot,Mirai,僵尸网络,DDoS"},
        {"ip": "176.65.148.180", "port": 23, "threat_type": "僵尸网络", "description": "Mirai僵尸网络,通过Telnet/SSH暴力破解扩散", "location": "德国", "tags": "Mirai,僵尸网络,DDoS"},
        {"ip": "196.251.115.253", "port": 5555, "threat_type": "后门", "description": "NjRAT远控木马,具备屏幕监控、键盘记录、密码窃取功能", "location": "荷兰/北荷兰省/阿姆斯特丹", "tags": "NjRAT,远控木马,后门"},
        {"ip": "2.4.130.229", "port": 8080, "threat_type": "后门", "description": "Nanocore远程访问木马,用于间谍活动和远程控制", "location": "法国/新阿基坦大区/蒙莫里永", "tags": "Nanocore,远控木马,间谍"},
        {"ip": "46.19.141.202", "port": 443, "threat_type": "后门", "description": "AsyncRAT后门,屏幕监控、键盘记录、文件窃取", "location": "瑞士/苏黎世州/苏黎世", "tags": "AsyncRAT,后门,远控"},
        {"ip": "181.131.216.154", "port": 8080, "threat_type": "后门", "description": "RemCos远控木马,可创建带恶意宏的Word文档", "location": "哥伦比亚/塞萨尔/巴耶杜帕尔", "tags": "RemCos,后门,宏病毒"},
        {"ip": "192.250.228.95", "port": 23, "threat_type": "僵尸网络", "description": "Mirai僵尸网络,针对IoT设备的DDoS攻击", "location": "新加坡", "tags": "Mirai,僵尸网络,DDoS"},
        {"ip": "149.28.98.229", "port": 443, "threat_type": "后门", "description": "AsyncRAT后门,针对中国境内民生领域联网系统", "location": "美国/佛罗里达州/迈阿密", "tags": "AsyncRAT,后门,APT"},
        {"ip": "185.174.101.218", "port": 80, "threat_type": "后门", "description": "RemCos远控木马,键盘记录、截屏、密码窃取", "location": "美国/加利福尼亚州/洛杉矶", "tags": "RemCos,后门,远控"},
        {"ip": "45.137.198.211", "port": 23, "threat_type": "僵尸网络", "description": "Mirai僵尸网络,通过漏洞利用和暴力破解扩散", "location": "荷兰/北荷兰省/阿姆斯特丹", "tags": "Mirai,僵尸网络,DDoS"},
        {"ip": "194.120.230.54", "port": 2323, "threat_type": "僵尸网络", "description": "Mirai僵尸网络(Meris变种),大规模DDoS攻击", "location": "荷兰/北荷兰省/阿姆斯特丹", "tags": "Meris,Mirai,僵尸网络"},
        {"ip": "37.120.141.162", "port": 443, "threat_type": "后门", "description": "Nanocore远程访问木马,间谍活动和数据窃取", "location": "荷兰/北荷兰省/阿姆斯特丹", "tags": "Nanocore,远控木马,间谍"},
        {"ip": "217.15.161.176", "port": 80, "threat_type": "僵尸网络", "description": "MooBot(Mirai变种),利用CVE漏洞入侵IoT设备", "location": "新加坡", "tags": "MooBot,Mirai,僵尸网络"},
        {"ip": "154.211.96.238", "port": 8080, "threat_type": "后门", "description": "Farfli远控木马,屏幕监控、键盘记录、DDoS攻击", "location": "新加坡", "tags": "Farfli,远控木马,后门"},
        {"ip": "94.122.78.238", "port": 23, "threat_type": "僵尸网络", "description": "gafgyt僵尸网络,基于IRC协议的IoT攻击", "location": "土耳其/伊斯坦布尔", "tags": "gafgyt,僵尸网络,IRC"},
        {"ip": "101.132.173.62", "port": 443, "threat_type": "C2服务器", "description": "Cobalt Strike C2服务器,可能用于渗透测试或恶意攻击", "location": "中国/上海", "tags": "CobaltStrike,C2,渗透"},
        {"ip": "103.189.140.124", "port": 4444, "threat_type": "C2服务器", "description": "Cobalt Strike C2服务器,后渗透阶段远控", "location": "中国/香港", "tags": "CobaltStrike,C2,远控"},
        {"ip": "134.122.140.185", "port": 8443, "threat_type": "C2服务器", "description": "Cobalt Strike C2服务器,HTTPS加密通信", "location": "美国/纽约", "tags": "CobaltStrike,C2,HTTPS"},
        {"ip": "179.43.186.214", "port": 80, "threat_type": "C2服务器", "description": "疑似Cobalt Strike C2,多个威胁情报源标记", "location": "瑞士", "tags": "CobaltStrike,C2,恶意"},
    ],
    "malicious_ports": [
        {"port": 4444, "threat_type": "Metasploit", "description": "Metasploit默认监听端口,Cobalt Strike默认通信端口"},
        {"port": 5555, "threat_type": "Android木马", "description": "AndroRAT默认端口,NjRAT常用端口"},
        {"port": 6666, "threat_type": "IRC僵尸网络", "description": "IRC Botnet常用端口,攻击者控制频道"},
        {"port": 7777, "threat_type": "远控木马", "description": "常见远控木马监听端口"},
        {"port": 8443, "threat_type": "C2服务器", "description": "Cobalt Strike HTTPS通信备用端口"},
        {"port": 8888, "threat_type": "远控木马", "description": "常见远控木马和代理木马端口"},
        {"port": 9999, "threat_type": "远控木马", "description": "常见远控木马监听端口"},
        {"port": 31337, "threat_type": "后门", "description": "Back Orifice默认端口,Elite后门常用"},
        {"port": 12345, "threat_type": "远控木马", "description": "NetBus/GirlFriend远控端口"},
        {"port": 27374, "threat_type": "远控木马", "description": "SubSeven远控木马默认端口"},
    ]
}


_cached_machine_id = None

def get_machine_id():
    global _cached_machine_id
    if _cached_machine_id:
        return _cached_machine_id

    parts = []

    try:
        result = subprocess.run(
            ["wmic", "diskdrive", "get", "serialnumber"],
            capture_output=True, timeout=2
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            line = line.strip()
            if line and "SerialNumber" not in line:
                parts.append(line)
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["wmic", "cpu", "get", "processorid"],
            capture_output=True, timeout=2
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            line = line.strip()
            if line and "ProcessorId" not in line:
                parts.append(line)
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["wmic", "baseboard", "get", "serialnumber"],
            capture_output=True, timeout=2
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            line = line.strip()
            if line and "SerialNumber" not in line:
                parts.append(line)
    except Exception:
        pass

    raw = "|".join(parts) if parts else os.environ.get("COMPUTERNAME", "unknown")
    _cached_machine_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return _cached_machine_id


class MaliciousIPManager:
    def __init__(self):
        self.db = DatabaseManager()
        self._ensure_builtin_data()

    def _ensure_builtin_data(self):
        count = self.db.fetch_one("SELECT COUNT(*) as cnt FROM black_ip")
        if count and count["cnt"] == 0:
            for item in BUILTIN_MALICIOUS_IPS["known_c2"]:
                self.db.insert("black_ip", {
                    "ip": item["ip"],
                    "port": item["port"],
                    "source": "builtin",
                    "threat_type": item["threat_type"],
                    "description": item["description"],
                    "location": item.get("location", ""),
                    "tags": item.get("tags", ""),
                })

    def get_all_black_ips(self):
        rows = self.db.fetch_all("SELECT * FROM black_ip ORDER BY id DESC")
        return [dict(row) for row in rows]

    def get_recent_black_ips(self, limit=100):
        rows = self.db.fetch_all("SELECT * FROM black_ip ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def add_black_ip(self, ip, port=0, threat_type="", description="", source="manual", status="active", location="", tags="", related_virus=""):
        existing = self.db.fetch_one("SELECT id FROM black_ip WHERE ip=? AND port=?", (ip, port))
        if existing:
            return False
        self.db.insert("black_ip", {
            "ip": ip,
            "port": port,
            "source": source,
            "threat_type": threat_type,
            "description": description,
            "status": status,
            "location": location,
            "tags": tags,
            "related_virus": related_virus,
        })
        return True

    def delete_black_ip(self, ip_id):
        self.db.delete("black_ip", "id=?", (ip_id,))

    def expire_black_ip(self, ip_id):
        self.db.update("black_ip", {"status": "expired"}, "id=?", (ip_id,))

    def activate_black_ip(self, ip_id):
        self.db.update("black_ip", {"status": "active"}, "id=?", (ip_id,))

    def update_black_ip_status(self, ip, port, status):
        existing = self.db.fetch_one("SELECT id FROM black_ip WHERE ip=? AND port=?", (ip, port))
        if existing:
            self.db.update("black_ip", {"status": status}, "id=?", (existing["id"],))
            return True
        return False

    def update_black_ip_fields(self, ip, port, threat_type="", description="", location="", tags="", related_virus="", status=""):
        existing = self.db.fetch_one("SELECT id FROM black_ip WHERE ip=? AND port=?", (ip, port))
        if existing:
            updates = {}
            if threat_type:
                updates["threat_type"] = threat_type
            if description:
                updates["description"] = description
            if location:
                updates["location"] = location
            if tags:
                updates["tags"] = tags
            if related_virus:
                updates["related_virus"] = related_virus
            if status:
                updates["status"] = status
            if updates:
                self.db.update("black_ip", updates, "id=?", (existing["id"],))
            return True
        return False

    def is_malicious_ip(self, ip, port=0):
        result = self.db.fetch_one("SELECT * FROM black_ip WHERE ip=? AND status='active'", (ip,))
        if result:
            return dict(result)
        if port > 0:
            port_result = self.db.fetch_one(
                "SELECT * FROM black_ip WHERE port=? AND ip='0.0.0.0' AND status='active'", (port,)
            )
            if port_result:
                return dict(port_result)
        return None

    def is_malicious_port(self, port):
        for item in BUILTIN_MALICIOUS_IPS["malicious_ports"]:
            if item["port"] == port:
                return item
        return None

    def search_black_ips(self, keyword):
        like = f"%{keyword}%"
        return self.db.fetch_all(
            "SELECT * FROM black_ip WHERE ip LIKE ? OR threat_type LIKE ? OR description LIKE ? OR location LIKE ? OR tags LIKE ? OR related_virus LIKE ? ORDER BY id DESC",
            (like, like, like, like, like, like)
        )

    def get_statistics(self):
        total = self.db.fetch_one("SELECT COUNT(*) as cnt FROM black_ip WHERE status='active'")
        by_type = self.db.fetch_all(
            "SELECT threat_type, COUNT(*) as cnt FROM black_ip WHERE status='active' GROUP BY threat_type ORDER BY cnt DESC"
        )
        expired = self.db.fetch_one("SELECT COUNT(*) as cnt FROM black_ip WHERE status='expired'")
        return {
            "total": total["cnt"] if total else 0,
            "by_type": [dict(row) for row in by_type] if by_type else [],
            "expired": expired["cnt"] if expired else 0,
        }

    def sync_from_server(self, server_url, secret_key="", client_info=None):
        try:
            if client_info is None:
                client_info = {}
            client_id = client_info.get("client_id", "")
            if not client_id:
                client_id = get_machine_id()
                client_info["client_id"] = client_id

            self._register_client(server_url, client_info, secret_key)

            max_id = self.db.fetch_one("SELECT COALESCE(MAX(id), 0) as max_id FROM black_ip")
            since_id = max_id["max_id"] if max_id else 0

            body = {
                "client_id": client_info.get("client_id", ""),
                "hostname": client_info.get("hostname", ""),
                "version": client_info.get("version", ""),
                "os": client_info.get("os", ""),
                "local_ips": [],
                "since_id": since_id,
                "full_sync": False,
                "t": str(int(datetime.now().timestamp())),
            }

            if secret_key:
                sign_fields = {"client_id": body["client_id"], "since_id": str(body["since_id"]), "full_sync": str(body["full_sync"]), "t": body["t"]}
                sorted_keys = sorted(sign_fields.keys())
                raw = "&".join(f"{k}={sign_fields[k]}" for k in sorted_keys)
                body["sign"] = hmac.new(
                    secret_key.encode("utf-8"),
                    raw.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

            data = json.dumps(body).encode("utf-8")
            url = f"{server_url.rstrip('/')}/api/v1/sync"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            if result.get("code") != 0:
                return {"success": False, "error": result.get("message", "同步失败")}

            ips = result.get("data", {}).get("ips", [])
            added = 0
            updated = 0

            all_known = {}
            for row in self.get_all_black_ips():
                key = f"{row['ip']}:{row['port']}"
                all_known[key] = row

            for ip_data in ips:
                ip = ip_data.get("ip", "")
                port = ip_data.get("port", 0)
                status = ip_data.get("status", "active")
                success = self.add_black_ip(
                    ip=ip,
                    port=port,
                    threat_type=ip_data.get("threat_type", ""),
                    description=ip_data.get("description", ""),
                    source=ip_data.get("source", ""),
                    status=status,
                    location=ip_data.get("location", ""),
                    tags=ip_data.get("tags", ""),
                    related_virus=ip_data.get("related_virus", ""),
                )
                if success:
                    added += 1
                else:
                    key = f"{ip}:{port}"
                    if key in all_known:
                        if self.update_black_ip_fields(
                            ip, port,
                            threat_type=ip_data.get("threat_type", ""),
                            description=ip_data.get("description", ""),
                            location=ip_data.get("location", ""),
                            tags=ip_data.get("tags", ""),
                            related_virus=ip_data.get("related_virus", ""),
                            status=status,
                        ):
                            updated += 1

            return {
                "success": True,
                "added": added,
                "updated": updated,
                "total": result.get("data", {}).get("total", 0),
                "server_time": result.get("data", {}).get("server_time", ""),
            }

        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
                msg = body.get("detail") or body.get("message") or str(e.code)
            except Exception:
                msg = f"HTTP {e.code}"
            return {"success": False, "error": msg}
        except urllib.error.URLError as e:
            return {"success": False, "error": f"无法连接到服务器: {e.reason}"}
        except json.JSONDecodeError:
            return {"success": False, "error": "服务器返回数据格式错误"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def push_to_server_only(self, server_url, secret_key="", client_info=None):
        try:
            if client_info is None:
                client_info = {}
            client_id = client_info.get("client_id", "")
            if not client_id:
                client_id = get_machine_id()
                client_info["client_id"] = client_id

            self._register_client(server_url, client_info, secret_key)

            local_ips = self.get_all_black_ips()
            ip_list = []
            for row in local_ips:
                ip_list.append({
                    "ip": row["ip"],
                    "port": row["port"],
                    "threat_type": row["threat_type"],
                    "description": row["description"],
                    "source": row["source"] if row["source"] else "client",
                    "status": row.get("status", "active"),
                    "location": row.get("location", ""),
                    "tags": row.get("tags", ""),
                    "related_virus": row.get("related_virus", ""),
                })

            body = {
                "client_id": client_info.get("client_id", ""),
                "hostname": client_info.get("hostname", ""),
                "version": client_info.get("version", ""),
                "os": client_info.get("os", ""),
                "local_ips": ip_list,
                "since_id": 0,
                "full_sync": False,
                "t": str(int(datetime.now().timestamp())),
            }

            if secret_key:
                sign_fields = {"client_id": body["client_id"], "since_id": "0", "full_sync": str(body["full_sync"]), "t": body["t"]}
                sorted_keys = sorted(sign_fields.keys())
                raw = "&".join(f"{k}={sign_fields[k]}" for k in sorted_keys)
                body["sign"] = hmac.new(
                    secret_key.encode("utf-8"),
                    raw.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

            data = json.dumps(body).encode("utf-8")
            url = f"{server_url.rstrip('/')}/api/v1/sync"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            if result.get("code") != 0:
                return {"success": False, "error": result.get("message", "推送失败")}

            return {
                "success": True,
                "pushed": len(ip_list),
                "server_time": result.get("data", {}).get("server_time", ""),
            }

        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
                msg = body.get("detail") or body.get("message") or str(e.code)
            except Exception:
                msg = f"HTTP {e.code}"
            return {"success": False, "error": msg}
        except urllib.error.URLError as e:
            return {"success": False, "error": f"无法连接到服务器: {e.reason}"}
        except json.JSONDecodeError:
            return {"success": False, "error": "服务器返回数据格式错误"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def sync_full_from_server(self, server_url, secret_key="", client_info=None):
        try:
            if client_info is None:
                client_info = {}
            client_id = client_info.get("client_id", "")
            if not client_id:
                client_id = get_machine_id()
                client_info["client_id"] = client_id

            self._register_client(server_url, client_info, secret_key)

            local_ips = self.get_all_black_ips()
            ip_list = []
            for row in local_ips:
                ip_list.append({
                    "ip": row["ip"],
                    "port": row["port"],
                    "threat_type": row["threat_type"],
                    "description": row["description"],
                    "source": row["source"] if row["source"] else "client",
                    "status": row.get("status", "active"),
                    "location": row.get("location", ""),
                    "tags": row.get("tags", ""),
                    "related_virus": row.get("related_virus", ""),
                })

            body = {
                "client_id": client_info.get("client_id", ""),
                "hostname": client_info.get("hostname", ""),
                "version": client_info.get("version", ""),
                "os": client_info.get("os", ""),
                "local_ips": ip_list,
                "since_id": 0,
                "full_sync": True,
                "t": str(int(datetime.now().timestamp())),
            }

            if secret_key:
                sign_fields = {"client_id": body["client_id"], "since_id": "0", "full_sync": str(body["full_sync"]), "t": body["t"]}
                sorted_keys = sorted(sign_fields.keys())
                raw = "&".join(f"{k}={sign_fields[k]}" for k in sorted_keys)
                body["sign"] = hmac.new(
                    secret_key.encode("utf-8"),
                    raw.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

            data = json.dumps(body).encode("utf-8")
            url = f"{server_url.rstrip('/')}/api/v1/sync"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            if result.get("code") != 0:
                return {"success": False, "error": result.get("message", "全量同步失败")}

            remote_ips = result.get("data", {}).get("ips", [])
            server_keys = set()
            added = 0
            updated = 0
            removed = 0

            all_known = {}
            for row in self.get_all_black_ips():
                key = f"{row['ip']}:{row['port']}"
                all_known[key] = row

            for ip_data in remote_ips:
                ip = ip_data.get("ip", "")
                port = ip_data.get("port", 0)
                status = ip_data.get("status", "active")
                key = f"{ip}:{port}"
                server_keys.add(key)

                success = self.add_black_ip(
                    ip=ip,
                    port=port,
                    threat_type=ip_data.get("threat_type", ""),
                    description=ip_data.get("description", ""),
                    source=ip_data.get("source", ""),
                    status=status,
                    location=ip_data.get("location", ""),
                    tags=ip_data.get("tags", ""),
                    related_virus=ip_data.get("related_virus", ""),
                )
                if success:
                    added += 1
                else:
                    if key in all_known:
                        if self.update_black_ip_fields(
                            ip, port,
                            threat_type=ip_data.get("threat_type", ""),
                            description=ip_data.get("description", ""),
                            location=ip_data.get("location", ""),
                            tags=ip_data.get("tags", ""),
                            related_virus=ip_data.get("related_virus", ""),
                            status=status,
                        ):
                            updated += 1

            for key, row in all_known.items():
                if key not in server_keys:
                    self.db.delete("black_ip", "id=?", (row["id"],))
                    removed += 1

            return {
                "success": True,
                "added": added,
                "updated": updated,
                "removed": removed,
                "total": result.get("data", {}).get("total", 0),
                "server_time": result.get("data", {}).get("server_time", ""),
            }

        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
                msg = body.get("detail") or body.get("message") or str(e.code)
            except Exception:
                msg = f"HTTP {e.code}"
            return {"success": False, "error": msg}
        except urllib.error.URLError as e:
            return {"success": False, "error": f"无法连接到服务器: {e.reason}"}
        except json.JSONDecodeError:
            return {"success": False, "error": "服务器返回数据格式错误"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _register_client(self, server_url, client_info, secret_key=""):
        try:
            body = {
                "client_id": client_info.get("client_id", ""),
                "hostname": client_info.get("hostname", ""),
                "version": client_info.get("version", ""),
                "os": client_info.get("os", ""),
                "t": str(int(datetime.now().timestamp())),
            }
            if secret_key:
                sorted_keys = sorted(body.keys())
                raw = "&".join(f"{k}={body[k]}" for k in sorted_keys if k != "sign")
                body["sign"] = hmac.new(
                    secret_key.encode("utf-8"),
                    raw.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

            data = json.dumps(body).encode("utf-8")
            url = f"{server_url.rstrip('/')}/api/v1/register"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass

    def push_to_server(self, server_url, secret_key="", client_info=None):
        try:
            if client_info is None:
                client_info = {}
            client_id = client_info.get("client_id", "")
            if not client_id:
                client_id = get_machine_id()
                client_info["client_id"] = client_id

            local_ips = self.get_all_black_ips()
            ip_list = []
            for row in local_ips:
                ip_list.append({
                    "ip": row["ip"],
                    "port": row["port"],
                    "threat_type": row["threat_type"],
                    "description": row["description"],
                    "source": row["source"] if row["source"] else "client",
                    "status": row.get("status", "active"),
                    "location": row.get("location", ""),
                    "tags": row.get("tags", ""),
                    "related_virus": row.get("related_virus", ""),
                })

            body = {
                "client_id": client_info.get("client_id", ""),
                "hostname": client_info.get("hostname", ""),
                "version": client_info.get("version", ""),
                "os": client_info.get("os", ""),
                "local_ips": ip_list,
                "since_id": 0,
                "t": str(int(datetime.now().timestamp())),
            }

            if secret_key:
                sign_fields = {"client_id": body["client_id"], "since_id": "0", "full_sync": "False", "t": body["t"]}
                sorted_keys = sorted(sign_fields.keys())
                raw = "&".join(f"{k}={sign_fields[k]}" for k in sorted_keys)
                body["sign"] = hmac.new(
                    secret_key.encode("utf-8"),
                    raw.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

            data = json.dumps(body).encode("utf-8")
            url = f"{server_url.rstrip('/')}/api/v1/sync"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            if result.get("code") != 0:
                return {"success": False, "error": result.get("message", "推送失败")}

            remote_ips = result.get("data", {}).get("ips", [])
            added = 0
            updated = 0

            all_known = {}
            for row in self.get_all_black_ips():
                key = f"{row['ip']}:{row['port']}"
                all_known[key] = row

            for ip_data in remote_ips:
                ip = ip_data.get("ip", "")
                port = ip_data.get("port", 0)
                status = ip_data.get("status", "active")
                success = self.add_black_ip(
                    ip=ip,
                    port=port,
                    threat_type=ip_data.get("threat_type", ""),
                    description=ip_data.get("description", ""),
                    source=ip_data.get("source", ""),
                    status=status,
                    location=ip_data.get("location", ""),
                    tags=ip_data.get("tags", ""),
                    related_virus=ip_data.get("related_virus", ""),
                )
                if success:
                    added += 1
                else:
                    key = f"{ip}:{port}"
                    if key in all_known and all_known[key].get("status") != status:
                        if self.update_black_ip_status(ip, port, status):
                            updated += 1

            return {
                "success": True,
                "added": added,
                "updated": updated,
                "total": result.get("data", {}).get("total", 0),
                "server_time": result.get("data", {}).get("server_time", ""),
            }

        except urllib.error.URLError as e:
            return {"success": False, "error": f"无法连接到服务器: {e.reason}"}
        except json.JSONDecodeError:
            return {"success": False, "error": "服务器返回数据格式错误"}
        except Exception as e:
            return {"success": False, "error": str(e)}
