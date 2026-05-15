from datetime import datetime, timedelta
from .db import DatabaseManager
from .network_detector import NetworkDetector


import threading

class ConnectionLogger:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.db = DatabaseManager()
                    cls._instance.detector = NetworkDetector()
        return cls._instance

    def __init__(self):
        pass

    def capture_snapshot(self):
        connections = self.detector.get_external_connections()
        count = self.detector.log_connections(connections)
        return count

    def scan_malicious_connections(self):
        conn = self.db._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE connection_log SET is_malicious=1 "
            "WHERE is_malicious=0 AND remote_ip IN (SELECT ip FROM black_ip WHERE status='active')"
        )
        conn.commit()
        return cursor.rowcount

    def get_logs(self, page=1, page_size=100, filters=None):
        conditions = []
        params = []

        if filters:
            if filters.get("malicious_only"):
                conditions.append("is_malicious=1")
            if filters.get("keyword"):
                conditions.append("(remote_ip LIKE ? OR process_name LIKE ?)")
                params.append(f"%{filters['keyword']}%")
                params.append(f"%{filters['keyword']}%")
            elif filters.get("remote_ip"):
                conditions.append("remote_ip LIKE ?")
                params.append(f"%{filters['remote_ip']}%")
            if filters.get("process_name"):
                conditions.append("process_name LIKE ?")
                params.append(f"%{filters['process_name']}%")
            if filters.get("start_time"):
                conditions.append("log_time >= ?")
                params.append(filters["start_time"])
            if filters.get("end_time"):
                conditions.append("log_time <= ?")
                params.append(filters["end_time"])

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        offset = (page - 1) * page_size

        count_sql = f"SELECT COUNT(*) as cnt FROM connection_log {where}"
        total = self.db.fetch_one(count_sql, params)["cnt"]

        data_sql = (
            "SELECT log_time, local_ip, local_port, remote_ip, remote_port, "
            "protocol, status, pid, process_name, process_path, "
            "process_cmdline, process_cwd, process_create_time, username, is_malicious "
            f"FROM connection_log {where} ORDER BY is_malicious DESC, log_time DESC LIMIT ? OFFSET ?"
        )
        data_params = params + [page_size, offset]
        rows = self.db.fetch_all(data_sql, data_params)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
            "data": [dict(row) for row in rows],
        }

    def get_logs_by_ip(self, remote_ip):
        rows = self.db.fetch_all(
            "SELECT * FROM connection_log WHERE remote_ip=? ORDER BY log_time DESC LIMIT 200",
            (remote_ip,)
        )
        return [dict(row) for row in rows]

    def get_logs_by_process(self, pid):
        rows = self.db.fetch_all(
            "SELECT * FROM connection_log WHERE pid=? ORDER BY log_time DESC LIMIT 200",
            (pid,)
        )
        return [dict(row) for row in rows]

    def get_malicious_logs_summary(self):
        rows = self.db.fetch_all(
            """SELECT remote_ip, remote_port, process_name, process_path, pid,
                      COUNT(*) as count, MAX(log_time) as last_seen
               FROM connection_log
               WHERE is_malicious=1
               GROUP BY remote_ip
               ORDER BY last_seen DESC
               LIMIT 100"""
        )
        return [dict(row) for row in rows]

    def get_connection_timeline(self, hours=24):
        start_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.db.fetch_all(
            """SELECT strftime('%Y-%m-%d %H:00', log_time) as hour,
                      COUNT(*) as total,
                      SUM(is_malicious) as malicious
               FROM connection_log
               WHERE log_time >= ?
               GROUP BY hour
               ORDER BY hour ASC""",
            (start_time,)
        )
        return [dict(row) for row in rows]

    def clear_old_logs(self, days=30):
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        self.db.delete("connection_log", "log_time < ?", (cutoff,))

    def export_logs(self, filepath, malicious_only=False):
        if malicious_only:
            rows = self.db.fetch_all(
                "SELECT * FROM connection_log WHERE is_malicious=1 ORDER BY is_malicious DESC, log_time DESC"
            )
        else:
            rows = self.db.fetch_all(
                "SELECT * FROM connection_log ORDER BY is_malicious DESC, log_time DESC"
            )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("时间,本地地址,本地端口,远程地址,远程端口,协议,状态,PID,进程名,进程路径,用户名,是否恶意\n")
            for row in rows:
                f.write(
                    f"{row['log_time']},{row['local_ip']},{row['local_port']},"
                    f"{row['remote_ip']},{row['remote_port']},{row['protocol']},"
                    f"{row['status']},{row['pid']},{row['process_name']},"
                    f"{row['process_path']},{row['username']},{row['is_malicious']}\n"
                )

        return len(rows)
