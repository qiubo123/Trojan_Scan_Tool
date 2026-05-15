import subprocess
import os
import re
import json
import csv
import io
import sqlite3
from datetime import datetime, timedelta
from xml.etree import ElementTree

from .db import DatabaseManager


class LogEntry:
    def __init__(self, log_type, time_str, source, event_id, level, message, detail=None):
        self.log_type = log_type
        self.time_str = time_str
        self.source = source
        self.event_id = event_id
        self.level = level
        self.message = message
        self.detail = detail or {}

    def to_dict(self):
        return {
            "log_type": self.log_type,
            "time_str": self.time_str,
            "source": self.source,
            "event_id": str(self.event_id),
            "level": self.level,
            "message": self.message[:500] if self.message else "",
            "detail": json.dumps(self.detail, ensure_ascii=False)[:1000] if self.detail else "",
        }


import threading

class LogCollector:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.db = DatabaseManager()
                    cls._instance._cache = {}
                    cls._instance._cache_time = 0
                    cls._instance._cached_logs = []
        return cls._instance

    def __init__(self):
        pass

    def collect_all(self, start_time=None, end_time=None):
        import time
        now = time.time()
        if self._cached_logs and now - self._cache_time < 30:
            return self._cached_logs

        all_logs = []
        all_logs.extend(self.collect_login_logs(start_time, end_time))
        all_logs.extend(self.collect_scheduled_task_logs(start_time, end_time))
        all_logs.extend(self.collect_powershell_logs(start_time, end_time))
        all_logs.extend(self.collect_firewall_logs(start_time, end_time))
        all_logs.extend(self.collect_browser_logs(start_time, end_time))
        all_logs.sort(key=lambda x: x.time_str, reverse=True)
        
        self._cached_logs = all_logs
        self._cache_time = now
        
        self._save_to_db(all_logs)
        return all_logs

    def _save_to_db(self, logs):
        try:
            from core.db import DatabaseManager
            import json
            db = DatabaseManager()
            db.delete("system_logs", "1=1", allow_all=True)
            records = []
            for log in logs:
                records.append({
                    "log_type": log.log_type or "",
                    "time_str": log.time_str or "",
                    "source": log.source or "",
                    "event_id": log.event_id or "",
                    "level": log.level or "",
                    "message": log.message[:500] if log.message else "",
                    "detail": json.dumps(log.detail, ensure_ascii=False)[:1000] if log.detail else "",
                })
            if records:
                db.insert_batch("system_logs", records)
        except Exception as e:
            print(f"保存系统日志到数据库失败: {e}")

    def _run_wevtutil(self, log_name, start_time=None, end_time=None, event_ids=None, max_events=200):
        try:
            if start_time and end_time:
                start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
                hours = int((end_dt - start_dt).total_seconds() / 3600) + 1
                hours = max(1, min(hours, 168))
            elif start_time:
                start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                hours = int((datetime.now() - start_dt).total_seconds() / 3600) + 1
                hours = max(1, min(hours, 168))
            else:
                hours = 24

            xpath = f"*[System[TimeCreated[timediff(@SystemTime) &lt;= {hours*3600000}]]]"
            if event_ids:
                id_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
                xpath = f"*[System[({id_filter}) and TimeCreated[timediff(@SystemTime) &lt;= {hours*3600000}]]]"

            cmd = [
                "wevtutil", "qe", log_name, "/q", xpath,
                "/f", "xml", "/c", str(max_events)
            ]
            result = subprocess.run(
                cmd, capture_output=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout.decode("utf-8", errors="replace")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return ""

    def _parse_wevtutil_xml(self, xml_text):
        entries = []
        try:
            root = ElementTree.fromstring(f"<root>{xml_text}</root>")
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            for event_elem in root.findall(".//ns:Event", ns):
                try:
                    sys_elem = event_elem.find("ns:System", ns)
                    if sys_elem is None:
                        continue

                    event_id_elem = sys_elem.find("ns:EventID", ns)
                    event_id = event_id_elem.text if event_id_elem is not None else ""

                    time_elem = sys_elem.find("ns:TimeCreated", ns)
                    time_str = time_elem.get("SystemTime") if time_elem is not None else ""

                    level_elem = sys_elem.find("ns:Level", ns)
                    level_map = {"1": "严重", "2": "错误", "3": "警告", "4": "信息", "0": "信息"}
                    level = level_map.get(level_elem.text if level_elem is not None else "", "信息")

                    provider_elem = sys_elem.find("ns:Provider", ns)
                    source = provider_elem.get("Name") if provider_elem is not None else ""

                    data_elem = event_elem.find("ns:EventData", ns)
                    detail = {}
                    if data_elem is not None:
                        for data_item in data_elem.findall("ns:Data", ns):
                            name = data_item.get("Name", "")
                            if name:
                                detail[name] = data_item.text or ""

                    if time_str:
                        try:
                            time_str = time_str.replace("T", " ").replace("Z", "")
                            if "." in time_str:
                                time_str = time_str.split(".")[0]
                        except Exception:
                            pass

                    entries.append({
                        "event_id": event_id,
                        "time": time_str,
                        "level": level,
                        "source": source,
                        "detail": detail,
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return entries

    def _backup_sqlite_db(self, db_path):
        try:
            import shutil
            temp = db_path + ".tmp_collect"
            shutil.copy2(db_path, temp)
            return temp
        except (IOError, PermissionError, OSError):
            return None

    def collect_huorong_logs(self, start_time=None, end_time=None):
        entries = []
        hr_data = r"C:\ProgramData\Huorong\Sysdiag"
        if not os.path.exists(hr_data):
            return entries

        if start_time:
            cutoff_ts = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S").timestamp()
        else:
            cutoff_ts = (datetime.now() - timedelta(hours=24)).timestamp()

        log_db = os.path.join(hr_data, "log.db")
        if os.path.exists(log_db):
            temp = self._backup_sqlite_db(log_db)
            if temp:
                try:
                    conn = sqlite3.connect(temp)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [t[0] for t in cursor.fetchall()]

                    for table in tables:
                        if "HrLog" in table:
                            cursor.execute(f'PRAGMA table_info("{table}")')
                            cols = [c[1] for c in cursor.fetchall()]
                            if "ts" in cols and "fname" in cols and "detail" in cols:
                                cursor.execute(
                                    f'SELECT ts, fname, detail FROM "{table}" WHERE ts > ? ORDER BY ts DESC LIMIT 200',
                                    (int(cutoff_ts),)
                                )
                                rows = cursor.fetchall()
                                for ts, fname, detail_json in rows:
                                    try:
                                        dt = datetime.fromtimestamp(ts)
                                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                        detail = json.loads(detail_json) if detail_json else {}
                                        sub_detail = detail.get("detail", {})

                                        level = "信息"
                                        treatment = sub_detail.get("treatment", 0)
                                        if treatment == 3:
                                            level = "警告"
                                        elif treatment == 2:
                                            level = "错误"

                                        msg_parts = []
                                        if fname == "instmon":
                                            procname = sub_detail.get("procname", "")
                                            cmdline = sub_detail.get("cmdline", "")
                                            msg_parts.append(f"进程: {procname or cmdline}")
                                            msg_parts.append(f"操作: 安装监控")
                                        elif fname == "update":
                                            msg_parts.append("病毒库更新")
                                        elif fname == "virus":
                                            threat_name = sub_detail.get("VirusName", sub_detail.get("name", ""))
                                            file_path = sub_detail.get("FilePath", sub_detail.get("pathname", ""))
                                            if threat_name:
                                                msg_parts.append(f"威胁: {threat_name}")
                                            if file_path:
                                                msg_parts.append(f"文件: {file_path}")
                                            level = "警告"
                                        elif fname == "regmon":
                                            reg_path = sub_detail.get("regpath", sub_detail.get("pathname", ""))
                                            if reg_path:
                                                msg_parts.append(f"注册表: {reg_path}")
                                        elif fname == "filemon":
                                            file_path = sub_detail.get("pathname", "")
                                            if file_path:
                                                msg_parts.append(f"文件: {file_path}")
                                        elif fname == "netmon":
                                            remote_ip = sub_detail.get("remote_ip", "")
                                            remote_port = sub_detail.get("remote_port", "")
                                            if remote_ip:
                                                msg_parts.append(f"远程: {remote_ip}:{remote_port}")
                                        elif fname == "webshell":
                                            web_path = sub_detail.get("pathname", "")
                                            if web_path:
                                                msg_parts.append(f"WebShell: {web_path}")
                                            level = "严重"

                                        msg = f"火绒-{fname}"
                                        if msg_parts:
                                            msg += " | " + " | ".join(msg_parts)

                                        entries.append(LogEntry(
                                            log_type="火绒安全日志",
                                            time_str=time_str,
                                            source=f"Huorong/{fname}",
                                            event_id=str(detail.get("id", "")),
                                            level=level,
                                            message=msg,
                                            detail=sub_detail,
                                        ))
                                    except Exception:
                                        continue
                    conn.close()
                except Exception:
                    pass
                finally:
                    try:
                        os.remove(temp)
                    except (IOError, PermissionError):
                        pass

        applog_db = os.path.join(hr_data, "applog.db")
        if os.path.exists(applog_db):
            temp = self._backup_sqlite_db(applog_db)
            if temp:
                try:
                    conn = sqlite3.connect(temp)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [t[0] for t in cursor.fetchall()]

                    for table in tables:
                        if "AppRunInfoList" in table:
                            cursor.execute(f'PRAGMA table_info("{table}")')
                            cols = [c[1] for c in cursor.fetchall()]
                            if "fn" in cols and "ts" in cols:
                                cursor.execute(
                                    f'SELECT fn, ts FROM "{table}" ORDER BY ts DESC LIMIT 200'
                                )
                                rows = cursor.fetchall()
                                for fn, ts in rows:
                                    try:
                                        ts_sec = ts / 10000000 - 11644473600
                                        if ts_sec < cutoff_ts:
                                            continue
                                        dt = datetime.fromtimestamp(ts_sec)
                                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                        proc_name = os.path.basename(fn) if fn else "?"
                                        entries.append(LogEntry(
                                            log_type="火绒安全日志",
                                            time_str=time_str,
                                            source="Huorong/AppRun",
                                            event_id="run",
                                            level="信息",
                                            message=f"火绒-程序运行: {proc_name}",
                                            detail={"path": fn, "proc_name": proc_name},
                                        ))
                                    except Exception:
                                        continue

                        elif "AppNetInfoList_days" in table:
                            cursor.execute(f'PRAGMA table_info("{table}")')
                            cols = [c[1] for c in cursor.fetchall()]
                            if "fn" in cols and "ts_day" in cols and "tx" in cols and "rx" in cols:
                                cursor.execute(
                                    f'SELECT fn, ts_day, tx, rx FROM "{table}" ORDER BY ts_day DESC LIMIT 200'
                                )
                                rows = cursor.fetchall()
                                for fn, ts_day, tx, rx in rows:
                                    try:
                                        if ts_day < cutoff_ts:
                                            continue
                                        dt = datetime.fromtimestamp(ts_day)
                                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                        proc_name = os.path.basename(fn) if fn else "?"
                                        tx_mb = tx / 1024 / 1024
                                        rx_mb = rx / 1024 / 1024
                                        entries.append(LogEntry(
                                            log_type="火绒安全日志",
                                            time_str=time_str,
                                            source="Huorong/NetFlow",
                                            event_id="netflow",
                                            level="信息",
                                            message=f"火绒-网络流量: {proc_name} | 上传: {tx_mb:.1f}MB | 下载: {rx_mb:.1f}MB",
                                            detail={"path": fn, "proc_name": proc_name, "tx": tx, "rx": rx},
                                        ))
                                    except Exception:
                                        continue
                    conn.close()
                except Exception:
                    pass
                finally:
                    try:
                        os.remove(temp)
                    except (IOError, PermissionError):
                        pass

        clean_log = os.path.join(hr_data, "Sysclean", "clean.log")
        if os.path.exists(clean_log):
            try:
                with open(clean_log, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                for line in lines[-100:]:
                    line = line.strip()
                    if line:
                        entries.append(LogEntry(
                            log_type="火绒安全日志",
                            time_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            source="Huorong/CleanLog",
                            event_id="clean",
                            level="信息",
                            message=f"火绒-扫描清理: {line[:200]}",
                            detail={"path": line},
                        ))
            except (IOError, PermissionError):
                pass

        return entries

    def collect_360_logs(self, start_time=None, end_time=None):
        entries = []
        _360_data = r"C:\ProgramData\360Safe"
        if not os.path.exists(_360_data):
            return entries

        if start_time:
            cutoff = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        else:
            cutoff = datetime.now() - timedelta(hours=24)

        log_files = [
            ("360ScanLog", "扫描日志"),
            ("360ScanDeepLog", "深度扫描日志"),
            ("360SoftMgrLog", "软件管理日志"),
        ]
        for log_name, log_label in log_files:
            log_path = os.path.join(_360_data, log_name)
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except (IOError, PermissionError):
                    try:
                        with open(log_path, "r", encoding="gbk", errors="replace") as f:
                            content = f.read()
                    except (IOError, PermissionError):
                        continue

                lines = content.split("\n")
                for line in lines[-200:]:
                    line = line.strip()
                    if not line:
                        continue
                    entries.append(LogEntry(
                        log_type="360安全日志",
                        time_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source=f"360/{log_label}",
                        event_id=log_name,
                        level="信息",
                        message=f"360-{log_label}: {line[:200]}",
                        detail={"content": line[:500]},
                    ))

        return entries

    def _run_ps(self, command, timeout=15):
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True, timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout.decode("utf-8", errors="replace").strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return ""

    def collect_login_logs(self, start_time=None, end_time=None):
        entries = []

        # 1. 获取所有本地用户账户
        user_accounts = {}
        output = self._run_ps(
            'Get-WmiObject -Class Win32_UserAccount -ErrorAction SilentlyContinue | '
            'Select-Object Name,FullName,Domain,SID,Disabled | ConvertTo-Json -Compress'
        )
        if output:
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for u in data:
                    sid = u.get("SID", "")
                    user_accounts[sid] = u
            except (json.JSONDecodeError, Exception):
                pass

        # 2. 获取当前登录会话 (Win32_LogonSession)
        output = self._run_ps(
            'Get-WmiObject -Class Win32_LogonSession -Filter "LogonType=2 OR LogonType=10" -ErrorAction SilentlyContinue | '
            'Select-Object LogonId,LogonType,StartTime,AuthenticationPackage | ConvertTo-Json -Compress'
        )
        if output:
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for s in data:
                    start_time_raw = s.get("StartTime", "")
                    if not start_time_raw:
                        continue
                    try:
                        wmi_time = start_time_raw.split(".")[0]
                        login_dt = datetime.strptime(wmi_time, "%Y%m%d%H%M%S")
                        time_str = login_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, IndexError):
                        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if start_time and time_str < start_time:
                        continue
                    if end_time and time_str > end_time:
                        continue
                    logon_id = s.get("LogonId", "")
                    logon_type = s.get("LogonType", "")
                    auth_pkg = s.get("AuthenticationPackage", "")
                    entries.append(LogEntry(
                        log_type="系统登录日志",
                        time_str=time_str,
                        source="Win32_LogonSession",
                        event_id=str(logon_id),
                        level="信息",
                        message=f"用户登录会话 | 认证包: {auth_pkg} | 登录类型: {logon_type}",
                        detail={
                            "logon_id": str(logon_id),
                            "logon_type": str(logon_type),
                            "authentication_package": auth_pkg,
                            "login_time": time_str,
                        },
                    ))
            except (json.JSONDecodeError, Exception):
                pass

        # 3. 获取用户配置文件最后使用时间
        output = self._run_ps(
            'Get-WmiObject -Class Win32_UserProfile -ErrorAction SilentlyContinue | '
            'Where-Object { $_.Special -eq $false } | '
            'Select-Object SID,LocalPath,LastUseTime | ConvertTo-Json -Compress'
        )
        if output:
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for p in data:
                    last_use = p.get("LastUseTime", "")
                    if not last_use:
                        continue
                    try:
                        wmi_time = last_use.split(".")[0]
                        last_dt = datetime.strptime(wmi_time, "%Y%m%d%H%M%S")
                        time_str = last_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, IndexError):
                        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if start_time and time_str < start_time:
                        continue
                    if end_time and time_str > end_time:
                        continue
                    sid = p.get("SID", "")
                    local_path = p.get("LocalPath", "")
                    username = os.path.basename(local_path) if local_path else sid
                    entries.append(LogEntry(
                        log_type="系统登录日志",
                        time_str=time_str,
                        source="Win32_UserProfile",
                        event_id="",
                        level="信息",
                        message=f"用户: {username} | 配置文件最后使用",
                        detail={
                            "username": username,
                            "sid": sid,
                            "login_time": time_str,
                        },
                    ))
            except (json.JSONDecodeError, Exception):
                pass

        # 4. 列出所有已启用的本地用户
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for sid, u in user_accounts.items():
            disabled = u.get("Disabled", False)
            if disabled:
                continue
            name = u.get("Name", "")
            full_name = u.get("FullName", "")
            display_name = full_name if full_name else name
            entries.append(LogEntry(
                log_type="系统登录日志",
                time_str=now_str,
                source="Win32_UserAccount",
                event_id="",
                level="信息",
                message=f"本地用户: {name} ({display_name}) - 已启用",
                detail={
                    "username": name,
                    "full_name": full_name,
                    "sid": sid,
                    "status": "已启用",
                },
            ))

        # 5. 如果以上都没有获取到，至少获取当前登录用户
        if not entries:
            output = self._run_ps(
                "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName",
                timeout=10
            )
            if output:
                username = output.split("\\")[-1] if "\\" in output else output
                entries.append(LogEntry(
                    log_type="系统登录日志",
                    time_str=now_str,
                    source="Win32_ComputerSystem",
                    event_id="",
                    level="信息",
                    message=f"当前登录用户: {username}",
                    detail={
                        "username": username,
                        "login_time": now_str,
                    },
                ))

        return entries

    def collect_scheduled_task_logs(self, start_time=None, end_time=None):
        entries = []

        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout = result.stdout.decode("utf-8", errors="replace")
            lines = stdout.strip().split("\n")
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    task_name = parts[0].strip().strip('"')
                    task_status = parts[1].strip().strip('"') if len(parts) > 1 else ""
                    task_command = parts[-1].strip().strip('"') if len(parts) > 1 else ""
                    entries.append(LogEntry(
                        log_type="计划任务日志",
                        time_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source="schtasks",
                        event_id="",
                        level="信息",
                        message=f"计划任务: {task_name} | 状态: {task_status}",
                        detail={"task_name": task_name, "status": task_status, "command": task_command},
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass

        task_event_ids = [106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 200, 201, 202, 203, 204]
        xml_text = self._run_wevtutil("Microsoft-Windows-TaskScheduler/Operational", start_time, end_time, task_event_ids, 200)
        parsed = self._parse_wevtutil_xml(xml_text)

        task_event_desc = {
            106: "任务已注册", 107: "任务已触发", 108: "任务已启动",
            109: "任务已完成", 110: "任务已停止", 111: "任务失败",
            112: "任务已跳过", 113: "任务错过触发", 114: "任务已更新",
            115: "任务已删除", 140: "任务已更新", 141: "任务已删除",
            200: "任务引擎启动", 201: "任务引擎停止", 202: "任务执行操作",
            203: "任务错过触发", 204: "任务未启动",
        }

        for p in parsed:
            eid = int(p["event_id"]) if p["event_id"].isdigit() else 0
            desc = task_event_desc.get(eid, f"任务计划事件 {eid}")
            task_name = p["detail"].get("TaskName", p["detail"].get("TaskName", ""))
            msg = desc
            if task_name:
                msg += f" | 任务: {task_name}"

            entries.append(LogEntry(
                log_type="计划任务日志",
                time_str=p["time"],
                source=p["source"],
                event_id=eid,
                level=p["level"],
                message=msg,
                detail=p["detail"],
            ))

        return entries

    def collect_powershell_logs(self, start_time=None, end_time=None):
        entries = []

        ps_event_ids = [400, 403, 4100, 4103, 4104, 4105, 4106, 4107, 4108, 53504, 53505, 53760, 53761]
        xml_text = self._run_wevtutil("Microsoft-Windows-PowerShell/Operational", start_time, end_time, ps_event_ids, 300)
        parsed = self._parse_wevtutil_xml(xml_text)

        ps_event_desc = {
            400: "PowerShell引擎启动", 403: "PowerShell引擎停止",
            4100: "命令执行(错误)", 4103: "命令执行(详细)",
            4104: "脚本块执行", 4105: "运行空间启动",
            4106: "运行空间停止", 4107: "脚本块已停止",
            4108: "模块加载", 53504: "远程连接建立",
            53505: "远程连接断开", 53760: "远程会话创建",
            53761: "远程会话断开",
        }

        for p in parsed:
            eid = int(p["event_id"]) if p["event_id"].isdigit() else 0
            desc = ps_event_desc.get(eid, f"PowerShell事件 {eid}")

            script_text = ""
            if eid == 4104:
                script_text = p["detail"].get("ScriptBlockText", "")
                if script_text:
                    script_text = script_text[:200]
            elif eid == 4103:
                command = p["detail"].get("Command", "")
                if command:
                    script_text = command[:200]

            msg = desc
            if script_text:
                msg += f" | 内容: {script_text}"

            entries.append(LogEntry(
                log_type="PowerShell运行日志",
                time_str=p["time"],
                source=p["source"],
                event_id=eid,
                level=p["level"],
                message=msg,
                detail=p["detail"],
            ))

        ps_history_path = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")
        if os.path.exists(ps_history_path):
            try:
                with open(ps_history_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                history_entries = []
                for line in lines[-100:]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        history_entries.append(line)

                if history_entries:
                    entries.append(LogEntry(
                        log_type="PowerShell运行日志",
                        time_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source="PSReadLine历史",
                        event_id="history",
                        level="信息",
                        message=f"PowerShell历史命令(最近{len(history_entries)}条)",
                        detail={"commands": history_entries},
                    ))
            except (IOError, PermissionError):
                pass

        return entries

    def collect_firewall_logs(self, start_time=None, end_time=None):
        entries = []

        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "monitor", "show", "firewall"],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout.decode("utf-8", errors="replace")
            current_rule = {}
            rule_count = 0
            for line in output.split("\n"):
                line = line.strip()
                if not line:
                    if current_rule.get("name"):
                        rule_count += 1
                        if rule_count <= 100:
                            entries.append(LogEntry(
                                log_type="防火墙外联日志",
                                time_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                source="netsh advfirewall",
                                event_id="rule",
                                level="信息",
                                message=f"防火墙规则: {current_rule.get('name', '?')} | 操作: {current_rule.get('action', '?')} | 协议: {current_rule.get('protocol', '?')}",
                                detail=dict(current_rule),
                            ))
                    current_rule = {}
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    current_rule[key.strip().lower()] = value.strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass

        firewall_event_ids = [2004, 2005, 2006, 2009, 2010, 2033, 2050, 2051, 2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 2060, 2061, 2062, 2063, 2064, 2065, 2066, 2067, 2068, 2069, 2070, 2071, 2072, 2073, 2074, 2075, 2076, 2077, 2078, 2079, 2080, 2081, 2082, 2083, 2084, 2085, 2086, 2087, 2088, 2089, 2090, 2091, 2092, 2093, 2094, 2095, 2096, 2097, 2098, 2099, 2100, 2101, 2102, 2103, 2104, 2105, 2106, 2107, 2108, 2109, 2110, 2111, 2112, 2113, 2114, 2115, 2116, 2117, 2118, 2119, 2120, 2121, 2122, 2123, 2124, 2125, 2126, 2127, 2128, 2129, 2130, 2131, 2132, 2133, 2134, 2135, 2136, 2137, 2138, 2139, 2140, 2141, 2142, 2143, 2144, 2145, 2146, 2147, 2148, 2149, 2150]
        xml_text = self._run_wevtutil("Security", start_time, end_time, firewall_event_ids, 200)
        parsed = self._parse_wevtutil_xml(xml_text)

        firewall_event_desc = {
            2004: "添加防火墙规则", 2005: "修改防火墙规则", 2006: "删除防火墙规则",
            2009: "防火墙规则生效", 2010: "防火墙规则失效",
            2033: "防火墙阻止连接", 2050: "防火墙配置更改",
            2051: "防火墙配置更改(详细)", 2052: "防火墙规则被禁用",
            2053: "防火墙规则被启用",
        }

        for p in parsed:
            eid = int(p["event_id"]) if p["event_id"].isdigit() else 0
            desc = firewall_event_desc.get(eid, f"防火墙事件 {eid}")
            rule_name = p["detail"].get("RuleName", p["detail"].get("Name", ""))
            msg = desc
            if rule_name:
                msg += f" | 规则: {rule_name}"

            entries.append(LogEntry(
                log_type="防火墙外联日志",
                time_str=p["time"],
                source=p["source"],
                event_id=eid,
                level=p["level"],
                message=msg,
                detail=p["detail"],
            ))

        return entries

    def collect_defender_logs(self, start_time=None, end_time=None):
        entries = []

        defender_event_ids = [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1150, 1151, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012]
        xml_text = self._run_wevtutil("Microsoft-Windows-Windows Defender/Operational", start_time, end_time, defender_event_ids, 300)
        parsed = self._parse_wevtutil_xml(xml_text)

        defender_event_desc = {
            1000: "Defender扫描启动", 1001: "Defender扫描完成",
            1002: "Defender扫描被中断", 1003: "Defender扫描暂停",
            1004: "Defender扫描恢复", 1005: "Defender扫描取消",
            1006: "Defender发现恶意软件", 1007: "Defender执行操作",
            1008: "Defender还原操作", 1009: "Defender删除历史记录",
            1010: "Defender禁用", 1011: "Defender启用",
            1012: "Defender配置更改", 1013: "Defender签名更新",
            1014: "Defender签名更新失败", 1015: "Defender检测到可疑行为",
            1116: "Defender检测到威胁", 1117: "Defender执行威胁操作",
            1118: "Defender威胁操作失败", 1119: "Defender威胁操作被覆盖",
            1120: "Defender威胁已解决", 1121: "Defender阻止执行",
            1122: "Defender阻止执行(部分)", 1123: "Defender资源已清理",
            1124: "Defender资源清理失败", 1125: "Defender资源清理被覆盖",
            1126: "Defender检测到PUA", 1127: "Defender阻止PUA",
            1128: "Defender检测到利用攻击", 1129: "Defender阻止利用攻击",
            1150: "Defender监控已暂停", 1151: "Defender监控已恢复",
            2000: "Defender实时保护生效", 2001: "Defender实时保护失效",
            2002: "Defender实时保护配置更改", 2003: "Defender实时保护清除威胁",
            5000: "Defender服务启动", 5001: "Defender服务停止",
            5007: "Defender配置更改", 5008: "Defender引擎失败",
            5009: "Defender反恶意软件引擎启动", 5010: "Defender反恶意软件引擎停止",
            5011: "Defender扫描已排队", 5012: "Defender扫描未排队",
        }

        for p in parsed:
            eid = int(p["event_id"]) if p["event_id"].isdigit() else 0
            desc = defender_event_desc.get(eid, f"Defender事件 {eid}")

            threat_name = p["detail"].get("Threat Name", p["detail"].get("DetectionName", ""))
            threat_path = p["detail"].get("Path", p["detail"].get("FilePath", ""))
            action = p["detail"].get("Action Name", p["detail"].get("Action", ""))

            msg = desc
            if threat_name:
                msg += f" | 威胁: {threat_name}"
            if threat_path:
                msg += f" | 路径: {threat_path}"
            if action:
                msg += f" | 操作: {action}"

            entries.append(LogEntry(
                log_type="Defender/杀毒日志",
                time_str=p["time"],
                source=p["source"],
                event_id=eid,
                level=p["level"],
                message=msg,
                detail=p["detail"],
            ))

        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-MpThreat | Select-Object -Property * | ConvertTo-Json"],
                capture_output=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout = result.stdout.decode("utf-8", errors="replace")
            if stdout.strip():
                threats = json.loads(stdout)
                if isinstance(threats, dict):
                    threats = [threats]
                for threat in threats:
                    threat_name = threat.get("ThreatName", "?")
                    threat_severity = threat.get("SeverityName", "?")
                    threat_status = threat.get("CurrentStatus", "?")
                    threat_time = threat.get("InitialDetectionTime", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    if isinstance(threat_time, datetime):
                        threat_time = threat_time.strftime("%Y-%m-%d %H:%M:%S")

                    entries.append(LogEntry(
                        log_type="Defender/杀毒日志",
                        time_str=str(threat_time),
                        source="Get-MpThreat",
                        event_id="mpthreat",
                        level="警告" if threat_severity in ("严重", "高") else "信息",
                        message=f"Defender威胁: {threat_name} | 严重程度: {threat_severity} | 状态: {threat_status}",
                        detail=threat,
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError):
            pass

        return entries

    def collect_browser_logs(self, start_time=None, end_time=None):
        entries = []

        if start_time:
            cutoff = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S").timestamp()
        else:
            cutoff = (datetime.now() - timedelta(hours=24)).timestamp()

        chromium_browsers = [
            ("Chrome", os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")),
            ("Edge", os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")),
            ("Brave", os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History")),
            ("Opera", os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera Stable\\History")),
            ("Vivaldi", os.path.expanduser("~\\AppData\\Local\\Vivaldi\\User Data\\Default\\History")),
            ("360安全浏览器", os.path.expanduser("~\\AppData\\Local\\360Chrome\\Chrome\\User Data\\Default\\History")),
            ("QQ浏览器", os.path.expanduser("~\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\Default\\History")),
            ("搜狗浏览器", os.path.expanduser("~\\AppData\\Local\\SogouExplorer\\User Data\\Default\\History")),
        ]

        for browser_name, history_path in chromium_browsers:
            if os.path.exists(history_path):
                try:
                    import shutil
                    temp_path = history_path + ".tmp_copy"
                    try:
                        shutil.copy2(history_path, temp_path)
                    except (IOError, PermissionError):
                        continue

                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200"
                    )
                    rows = cursor.fetchall()
                    conn.close()

                    try:
                        os.remove(temp_path)
                    except (IOError, PermissionError):
                        pass

                    for url, title, visit_time in rows:
                        try:
                            visit_dt = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                            if visit_dt.timestamp() < cutoff:
                                continue
                            time_str = visit_dt.strftime("%Y-%m-%d %H:%M:%S")
                            entries.append(LogEntry(
                                log_type="浏览器下载与访问日志",
                                time_str=time_str,
                                source=f"{browser_name}历史记录",
                                event_id="visit",
                                level="信息",
                                message=f"[{browser_name}] 访问: {title or url[:100]}",
                                detail={"url": url, "title": title or ""},
                            ))
                        except Exception:
                            continue

                    downloads_path = os.path.join(os.path.dirname(history_path), "History")
                    if os.path.exists(downloads_path):
                        try:
                            shutil.copy2(downloads_path, temp_path)
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            cursor.execute(
                                "SELECT target_path, start_time, end_time, received_bytes, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 100"
                            )
                            download_rows = cursor.fetchall()
                            conn.close()
                            try:
                                os.remove(temp_path)
                            except (IOError, PermissionError):
                                pass

                            for target_path, start_time, end_time, received, total in download_rows:
                                try:
                                    start_dt = datetime(1601, 1, 1) + timedelta(microseconds=start_time)
                                    if start_dt.timestamp() < cutoff:
                                        continue
                                    time_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
                                    entries.append(LogEntry(
                                        log_type="浏览器下载与访问日志",
                                        time_str=time_str,
                                        source=f"{browser_name}下载记录",
                                        event_id="download",
                                        level="信息",
                                        message=f"[{browser_name}] 下载: {os.path.basename(target_path)} ({received}/{total}字节)",
                                        detail={"path": target_path, "received": received, "total": total},
                                    ))
                                except Exception:
                                    continue
                        except Exception:
                            pass

                except Exception:
                    pass

        firefox_history = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
        if os.path.exists(firefox_history):
            try:
                import glob as glob_mod
                profile_dirs = glob_mod.glob(os.path.join(firefox_history, "*", "places.sqlite"))
                for places_path in profile_dirs:
                    try:
                        import shutil
                        temp_path = places_path + ".tmp_copy"
                        shutil.copy2(places_path, temp_path)
                        conn = sqlite3.connect(temp_path)
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 200"
                        )
                        rows = cursor.fetchall()
                        conn.close()
                        os.remove(temp_path)

                        for url, title, visit_date in rows:
                            if not visit_date:
                                continue
                            try:
                                visit_dt = datetime(1970, 1, 1) + timedelta(microseconds=visit_date)
                                if visit_dt.timestamp() < cutoff:
                                    continue
                                time_str = visit_dt.strftime("%Y-%m-%d %H:%M:%S")
                                entries.append(LogEntry(
                                    log_type="浏览器下载与访问日志",
                                    time_str=time_str,
                                    source="Firefox历史记录",
                                    event_id="visit",
                                    level="信息",
                                    message=f"[Firefox] 访问: {title or url[:100]}",
                                    detail={"url": url, "title": title or ""},
                                ))
                            except Exception:
                                continue
                    except Exception:
                        continue
            except Exception:
                pass

        return entries