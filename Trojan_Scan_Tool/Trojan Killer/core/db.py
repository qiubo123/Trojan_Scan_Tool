import sqlite3
import os
import sys
import threading
from datetime import datetime


def get_data_dir():
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data")

DB_DIR = get_data_dir()
DB_PATH = os.path.join(DB_DIR, "trojan_killer.db")


class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._local = threading.local()
                    cls._instance._init_lock = threading.Lock()
        return cls._instance

    def _get_connection(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            os.makedirs(DB_DIR, exist_ok=True)
            self._local.conn = sqlite3.connect(DB_PATH)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn.execute("PRAGMA cache_size=-8000")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA temp_store=MEMORY")
            self._local.conn.execute("PRAGMA mmap_size=268435456")
        return self._local.conn

    def init_db(self):
        with self._init_lock:
            conn = self._get_connection()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS black_ip (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    port INTEGER DEFAULT 0,
                    source TEXT DEFAULT 'manual',
                    threat_type TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS scan_record (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    scan_status TEXT DEFAULT 'running',
                    total_count INTEGER DEFAULT 0,
                    threat_count INTEGER DEFAULT 0,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS threat_found (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER DEFAULT 0,
                    threat_type TEXT DEFAULT '',
                    threat_name TEXT DEFAULT '',
                    threat_path TEXT DEFAULT '',
                    threat_ip TEXT DEFAULT '',
                    threat_port INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'middle',
                    process_name TEXT DEFAULT '',
                    process_pid INTEGER DEFAULT 0,
                    description TEXT DEFAULT '',
                    suggestion TEXT DEFAULT '',
                    status TEXT DEFAULT 'unhandled',
                    found_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS connection_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    local_ip TEXT DEFAULT '',
                    local_port INTEGER DEFAULT 0,
                    remote_ip TEXT DEFAULT '',
                    remote_port INTEGER DEFAULT 0,
                    protocol TEXT DEFAULT 'tcp',
                    status TEXT DEFAULT '',
                    pid INTEGER DEFAULT 0,
                    process_name TEXT DEFAULT '',
                    process_path TEXT DEFAULT '',
                    process_cmdline TEXT DEFAULT '',
                    process_cwd TEXT DEFAULT '',
                    process_create_time TEXT DEFAULT '',
                    username TEXT DEFAULT '',
                    is_malicious INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS process_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    name TEXT DEFAULT '',
                    path TEXT DEFAULT '',
                    cmdline TEXT DEFAULT '',
                    cwd TEXT DEFAULT '',
                    username TEXT DEFAULT '',
                    cpu_usage REAL DEFAULT 0,
                    memory_usage INTEGER DEFAULT 0,
                    thread_count INTEGER DEFAULT 0,
                    handle_count INTEGER DEFAULT 0,
                    create_time TEXT DEFAULT '',
                    suspicious INTEGER DEFAULT 0,
                    suspicious_reason TEXT DEFAULT '',
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS startup_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT DEFAULT '',
                    path TEXT DEFAULT '',
                    command TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    startup_type TEXT DEFAULT '',
                    publisher TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS user_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT DEFAULT '',
                    full_name TEXT DEFAULT '',
                    sid TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    is_admin INTEGER DEFAULT 0,
                    is_suspicious INTEGER DEFAULT 0,
                    suspicious_reason TEXT DEFAULT '',
                    last_login TEXT DEFAULT '',
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS software_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    publisher TEXT DEFAULT '',
                    install_date TEXT DEFAULT '',
                    install_location TEXT DEFAULT '',
                    uninstall_string TEXT DEFAULT '',
                    size_mb REAL DEFAULT 0,
                    is_vpn INTEGER DEFAULT 0,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_type TEXT DEFAULT '',
                    time_str TEXT DEFAULT '',
                    source TEXT DEFAULT '',
                    event_id TEXT DEFAULT '',
                    level TEXT DEFAULT '',
                    message TEXT DEFAULT '',
                    detail TEXT DEFAULT '',
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_connection_log_time ON connection_log(log_time DESC);
                CREATE INDEX IF NOT EXISTS idx_connection_log_remote_ip ON connection_log(remote_ip);
                CREATE INDEX IF NOT EXISTS idx_threat_found_time ON threat_found(found_time DESC);
                CREATE INDEX IF NOT EXISTS idx_black_ip_ip ON black_ip(ip);
                CREATE INDEX IF NOT EXISTS idx_process_info_pid ON process_info(pid);
                CREATE INDEX IF NOT EXISTS idx_process_info_scan_time ON process_info(scan_time DESC);
                CREATE INDEX IF NOT EXISTS idx_startup_items_name ON startup_items(name);
                CREATE INDEX IF NOT EXISTS idx_user_accounts_name ON user_accounts(name);
                CREATE INDEX IF NOT EXISTS idx_software_info_name ON software_info(name);
                CREATE INDEX IF NOT EXISTS idx_system_logs_time ON system_logs(scan_time DESC);
            """)
            try:
                conn.execute("ALTER TABLE black_ip ADD COLUMN status TEXT DEFAULT 'active'")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE black_ip ADD COLUMN location TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE black_ip ADD COLUMN tags TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE black_ip ADD COLUMN related_virus TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE connection_log ADD COLUMN process_cmdline TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE connection_log ADD COLUMN process_cwd TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE connection_log ADD COLUMN process_create_time TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                conn.execute("DROP TABLE IF EXISTS whitelist_process")
            except Exception:
                pass
            try:
                conn.execute("DROP TABLE IF EXISTS whitelist_file")
            except Exception:
                pass
            conn.commit()

    def execute(self, sql, params=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        conn.commit()
        return cursor

    def fetch_one(self, sql, params=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        return cursor.fetchone()

    def fetch_all(self, sql, params=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        return cursor.fetchall()

    def insert(self, table, data):
        conn = self._get_connection()
        cursor = conn.cursor()
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        cursor.execute(sql, list(data.values()))
        conn.commit()
        return cursor.lastrowid

    def insert_batch(self, table, data_list):
        if not data_list:
            return
        conn = self._get_connection()
        cursor = conn.cursor()
        columns = ", ".join(data_list[0].keys())
        placeholders = ", ".join(["?"] * len(data_list[0]))
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        cursor.executemany(sql, [list(d.values()) for d in data_list])
        conn.commit()

    def _validate_condition(self, condition, allow_all=False):
        if not allow_all and (not condition or condition.strip() == "1=1"):
            import logging
            logging.warning(f"检测到无条件删除/更新操作: {condition}")
        return condition

    def update(self, table, data, condition, params=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{k}=?" for k in data.keys()])
        condition = self._validate_condition(condition)
        sql = f"UPDATE {table} SET {set_clause} WHERE {condition}"
        all_params = list(data.values()) + (list(params) if params else [])
        cursor.execute(sql, all_params)
        conn.commit()
        return cursor.rowcount

    def delete(self, table, condition, params=None, allow_all=False):
        conn = self._get_connection()
        cursor = conn.cursor()
        condition = self._validate_condition(condition, allow_all)
        sql = f"DELETE FROM {table} WHERE {condition}"
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        conn.commit()
        return cursor.rowcount

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
